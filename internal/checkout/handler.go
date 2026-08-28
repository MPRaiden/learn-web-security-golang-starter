package checkout

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/cart"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/integrations/acorn"
	"github.com/bootdotdev/learn-web-security/internal/integrations/pawpal"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type pageView struct {
	templates.Page
	Items       []cart.Item
	TotalCents  int64
	DisplayName string
	Error       string
}

type processingPageView struct {
	templates.Page
	OrderID     int64
	DisplayName string
}

type Handler struct {
	cartStore        *cart.Store
	orderStore       *orders.Store
	accountStore     *accounts.Store
	renderer         *templates.Renderer
	logger           *logging.Logger
	pawPalAPIKey     string
	fulfillmentDelay time.Duration
}

func NewHandler(cartStore *cart.Store, orderStore *orders.Store, accountStore *accounts.Store, renderer *templates.Renderer, logger *logging.Logger, pawPalAPIKey string, fulfillmentDelay time.Duration) *Handler {
	return &Handler{
		cartStore:        cartStore,
		orderStore:       orderStore,
		accountStore:     accountStore,
		renderer:         renderer,
		logger:           logger,
		pawPalAPIKey:     pawPalAPIKey,
		fulfillmentDelay: fulfillmentDelay,
	}
}

func (handler *Handler) Page(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	items, err := handler.cartStore.ListItems(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if len(items) == 0 || firstUnavailable(items) != nil {
		http.Redirect(responseWriter, request, "/cart", http.StatusFound)
		return
	}
	if err := handler.renderPage(responseWriter, http.StatusOK, current, items, ""); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) Submit(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	items, err := handler.cartStore.ListItems(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if len(items) == 0 {
		http.Redirect(responseWriter, request, "/cart", http.StatusFound)
		return
	}
	if unavailableItem := firstUnavailable(items); unavailableItem != nil {
		handler.renderCheckoutError(responseWriter, request, http.StatusConflict, current, items, unavailableItem.Name+" is no longer available in the requested quantity. Update your cart before checking out.")
		return
	}
	shippingDetails, discountCents, valid := handler.parseCheckoutForm(responseWriter, request)
	if !valid {
		return
	}
	if shippingDetails.Name == "" || shippingDetails.Address == "" || shippingDetails.City == "" || shippingDetails.Region == "" || shippingDetails.PostalCode == "" {
		handler.renderCheckoutError(responseWriter, request, http.StatusBadRequest, current, items, "All shipping fields are required")
		return
	}
	_, err = acorn.Reserve(request.Context(), acorn.Request{
		Name:       shippingDetails.Name,
		Address:    shippingDetails.Address,
		City:       shippingDetails.City,
		Region:     shippingDetails.Region,
		PostalCode: shippingDetails.PostalCode,
	}, handler.fulfillmentDelay)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	items, err = handler.cartStore.ListItems(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if len(items) == 0 {
		http.Redirect(responseWriter, request, "/cart", http.StatusFound)
		return
	}
	if unavailableItem := firstUnavailable(items); unavailableItem != nil {
		handler.renderCheckoutError(responseWriter, request, http.StatusConflict, current, items, unavailableItem.Name+" is no longer available in the requested quantity. Update your cart before checking out.")
		return
	}
	adminNotes := "PawPal redirect approved. Ship to " + shippingDetails.Name + ", " + shippingDetails.Address + ", " + shippingDetails.City + ", " + shippingDetails.Region + " " + shippingDetails.PostalCode + "."
	order, err := handler.orderStore.CreateFromCart(request.Context(), current.User.ID, items, discountCents, adminNotes)
	if errors.Is(err, orders.ErrInsufficientInventory) {
		currentItems, listErr := handler.cartStore.ListItems(request.Context(), current.User.ID)
		if listErr != nil {
			handler.internalError(responseWriter, request, listErr)
			return
		}
		handler.renderCheckoutError(responseWriter, request, http.StatusConflict, current, currentItems, orders.InsufficientInventoryMessage)
		return
	}
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	_ = handler.logger.Event("checkout_completed", map[string]any{
		"userId":             current.User.ID,
		"email":              current.User.Email,
		"orderId":            order.ID,
		"totalCents":         order.TotalCents,
		"pawPalReference":    pawpal.CreateReference(order.ID, order.TotalCents, handler.pawPalAPIKey),
		"shippingName":       shippingDetails.Name,
		"shippingAddress":    shippingDetails.Address,
		"shippingCity":       shippingDetails.City,
		"shippingRegion":     shippingDetails.Region,
		"shippingPostalCode": shippingDetails.PostalCode,
		"adminNotes":         adminNotes,
	})
	http.Redirect(responseWriter, request, "/pawpal/processing/"+strconv.FormatInt(order.ID, 10), http.StatusFound)
}

func (handler *Handler) Processing(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	orderID, valid := httpx.ParseSafeInteger(request.PathValue("orderId"))
	if !valid {
		handler.orderNotFound(responseWriter)
		return
	}
	order, found, err := handler.orderStore.FindByID(request.Context(), orderID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || order.UserID != current.User.ID {
		handler.orderNotFound(responseWriter)
		return
	}
	view := processingPageView{
		Title:       "PawPal Processing",
		OrderID:     order.ID,
		DisplayName: current.User.DisplayName,
	}
	if err := handler.renderer.Render(responseWriter, http.StatusOK, "pawpal-processing", view); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) parseCheckoutForm(responseWriter http.ResponseWriter, request *http.Request) (orders.ShippingDetails, int64, bool) {
	fieldNames := []string{"shippingName", "shippingAddress", "shippingCity", "shippingRegion", "shippingPostalCode"}
	fieldValues := make(map[string]string, len(fieldNames))
	for _, fieldName := range fieldNames {
		fieldValue, err := httpx.FormValue(request, fieldName)
		if err != nil {
			handler.errorPage(responseWriter, http.StatusBadRequest, "Invalid Request", "The submitted form is invalid.")
			return orders.ShippingDetails{}, 0, false
		}
		fieldValues[fieldName] = fieldValue
	}
	return orders.ShippingDetails{
		Name:       strings.TrimSpace(fieldValues["shippingName"]),
		Address:    strings.TrimSpace(fieldValues["shippingAddress"]),
		City:       strings.TrimSpace(fieldValues["shippingCity"]),
		Region:     strings.TrimSpace(fieldValues["shippingRegion"]),
		PostalCode: strings.TrimSpace(fieldValues["shippingPostalCode"]),
	}, parseDiscount(request.PostForm.Get("discountCents")), true
}

func (handler *Handler) renderPage(responseWriter http.ResponseWriter, statusCode int, current accounts.CurrentSession, items []cart.Item, errorMessage string) error {
	return handler.renderer.Render(responseWriter, statusCode, "checkout", pageView{
		Title:       "Checkout",
		Items:       items,
		TotalCents:  cart.TotalCents(items),
		DisplayName: current.User.DisplayName,
		Error:       errorMessage,
	})
}

func (handler *Handler) renderCheckoutError(responseWriter http.ResponseWriter, request *http.Request, statusCode int, current accounts.CurrentSession, items []cart.Item, message string) {
	if err := handler.renderPage(responseWriter, statusCode, current, items, message); err != nil {
		handler.internalError(responseWriter, request, err)
	}
}

func (handler *Handler) requireAuth(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Require(responseWriter, request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	return current, found
}

func (handler *Handler) orderNotFound(responseWriter http.ResponseWriter) {
	handler.errorPage(responseWriter, http.StatusNotFound, "Order Not Found", "We couldn't find that order.")
}

func (handler *Handler) errorPage(responseWriter http.ResponseWriter, statusCode int, heading, message string) {
	if err := httpx.RespondWithErrorPage(responseWriter, handler.renderer, statusCode, heading, message); err != nil {
		http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	handler.errorPage(responseWriter, http.StatusInternalServerError, "Unhandled Error", err.Error())
}

func firstUnavailable(items []cart.Item) *cart.Item {
	for itemIndex := range items {
		if cart.ItemAvailability(items[itemIndex]) != cart.Available {
			return &items[itemIndex]
		}
	}
	return nil
}

func parseDiscount(value string) int64 {
	discount, _ := strconv.ParseInt(value, 10, 64)
	return discount
}
