-- name: ListReviewsForUser :many
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
WHERE reviews.user_id = ?
ORDER BY reviews.created_at DESC, reviews.id DESC;

-- name: GetReviewByID :one
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
WHERE reviews.id = ?;

-- name: ActiveReviewProductExists :one
SELECT EXISTS(
  SELECT 1
  FROM products
  WHERE id = ? AND is_active = 1
);

-- name: CreateReview :exec
INSERT INTO reviews (user_id, product_id, rating, body)
VALUES (?, ?, ?, ?);

-- name: UpdateReview :exec
UPDATE reviews
SET rating = ?, body = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteReview :exec
DELETE FROM reviews
WHERE id = ?;
