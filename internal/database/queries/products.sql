-- name: ListActiveProducts :many
SELECT id, name, description, image_path, price_cents, cost_cents, inventory_count, is_active, created_at
FROM products
WHERE is_active = 1
ORDER BY name
LIMIT ?;

-- name: SearchActiveProducts :many
SELECT id, name, description, image_path, price_cents, cost_cents, inventory_count, is_active, created_at
FROM products
WHERE is_active = 1
  AND (name LIKE sqlc.arg(pattern) OR description LIKE sqlc.arg(pattern))
ORDER BY name
LIMIT sqlc.arg(max_results);

-- name: GetActiveProduct :one
SELECT id, name, description, image_path, price_cents, cost_cents, inventory_count, is_active, created_at
FROM products
WHERE id = ? AND is_active = 1;

-- name: ListReviewsForProduct :many
SELECT
  reviews.id,
  reviews.user_id,
  reviews.product_id,
  products.name AS product_name,
  users.display_name AS reviewer_name,
  reviews.rating,
  reviews.body,
  reviews.created_at,
  reviews.updated_at
FROM reviews
JOIN users ON users.id = reviews.user_id
JOIN products ON products.id = reviews.product_id
WHERE reviews.product_id = ?
ORDER BY reviews.created_at DESC, reviews.id DESC;
