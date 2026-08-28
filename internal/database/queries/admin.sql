-- name: ListAllProducts :many
SELECT id, name, description, image_path, price_cents, cost_cents, inventory_count, is_active, created_at
FROM products
ORDER BY name;

-- name: GetProductByID :one
SELECT id, name, description, image_path, price_cents, cost_cents, inventory_count, is_active, created_at
FROM products
WHERE id = ?;

-- name: CreateProduct :one
INSERT INTO products (name, description, image_path, price_cents, cost_cents, inventory_count, is_active)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id, name, description, image_path, price_cents, cost_cents, inventory_count, is_active, created_at;

-- name: UpdateProduct :one
UPDATE products
SET
  name = ?,
  description = ?,
  image_path = ?,
  price_cents = ?,
  cost_cents = ?,
  inventory_count = ?,
  is_active = ?
WHERE id = ?
RETURNING id, name, description, image_path, price_cents, cost_cents, inventory_count, is_active, created_at;
