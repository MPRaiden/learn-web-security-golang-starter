-- name: ListCartItems :many
SELECT
  cart_items.id,
  cart_items.user_id,
  cart_items.product_id,
  cart_items.quantity,
  cart_items.created_at,
  cart_items.updated_at,
  products.name,
  products.image_path,
  products.price_cents,
  products.inventory_count,
  products.is_active,
  products.price_cents * cart_items.quantity AS line_total_cents
FROM cart_items
JOIN products ON products.id = cart_items.product_id
WHERE cart_items.user_id = ?
ORDER BY cart_items.created_at;

-- name: ActiveCartProductExists :one
SELECT EXISTS(
  SELECT 1
  FROM products
  WHERE id = ? AND is_active = 1
);

-- name: AddProductToCart :execresult
INSERT INTO cart_items (user_id, product_id, quantity)
SELECT sqlc.arg(user_id), products.id, sqlc.arg(quantity)
FROM products
WHERE products.id = sqlc.arg(product_id)
  AND products.is_active = 1
  AND products.inventory_count >= sqlc.arg(quantity)
ON CONFLICT (user_id, product_id) DO UPDATE SET
  quantity = cart_items.quantity + excluded.quantity,
  updated_at = CURRENT_TIMESTAMP
WHERE cart_items.quantity + excluded.quantity <= 99
  AND cart_items.quantity + excluded.quantity <= (
    SELECT inventory_count
    FROM products
    WHERE products.id = excluded.product_id
      AND products.is_active = 1
  );

-- name: UpdateCartItemQuantity :execresult
UPDATE cart_items
SET quantity = sqlc.arg(quantity), updated_at = CURRENT_TIMESTAMP
WHERE user_id = sqlc.arg(user_id)
  AND product_id = sqlc.arg(product_id)
  AND sqlc.arg(quantity) <= (
    SELECT inventory_count
    FROM products
    WHERE products.id = cart_items.product_id
      AND products.is_active = 1
  );

-- name: RemoveCartItem :exec
DELETE FROM cart_items
WHERE user_id = ? AND product_id = ?;
