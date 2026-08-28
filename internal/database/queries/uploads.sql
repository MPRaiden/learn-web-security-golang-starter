-- name: CreateUploadedFile :one
INSERT INTO uploaded_files (user_id, original_name, storage_path, content_type)
VALUES (?, ?, ?, ?)
RETURNING id;

-- name: GetUploadedFileByID :one
SELECT
  uploaded_files.id,
  uploaded_files.user_id,
  users.display_name AS customer_name,
  users.email AS customer_email,
  uploaded_files.original_name,
  uploaded_files.storage_path,
  uploaded_files.content_type,
  uploaded_files.created_at
FROM uploaded_files
JOIN users ON users.id = uploaded_files.user_id
WHERE uploaded_files.id = ?;

-- name: ListUploadedFilesForUser :many
SELECT
  uploaded_files.id,
  uploaded_files.user_id,
  users.display_name AS customer_name,
  users.email AS customer_email,
  uploaded_files.original_name,
  uploaded_files.storage_path,
  uploaded_files.content_type,
  uploaded_files.created_at
FROM uploaded_files
JOIN users ON users.id = uploaded_files.user_id
WHERE uploaded_files.user_id = ?
ORDER BY uploaded_files.created_at DESC, uploaded_files.id DESC;

-- name: ListAllUploadedFiles :many
SELECT
  uploaded_files.id,
  uploaded_files.user_id,
  users.display_name AS customer_name,
  users.email AS customer_email,
  uploaded_files.original_name,
  uploaded_files.storage_path,
  uploaded_files.content_type,
  uploaded_files.created_at
FROM uploaded_files
JOIN users ON users.id = uploaded_files.user_id
ORDER BY uploaded_files.created_at DESC, uploaded_files.id DESC;

-- name: ListImportedTaxDocuments :many
SELECT
  imported_tax_documents.id,
  imported_tax_documents.imported_by_user_id,
  users.display_name AS imported_by_name,
  imported_tax_documents.original_name,
  imported_tax_documents.storage_path,
  imported_tax_documents.content_type,
  imported_tax_documents.created_at
FROM imported_tax_documents
JOIN users ON users.id = imported_tax_documents.imported_by_user_id
ORDER BY imported_tax_documents.created_at DESC, imported_tax_documents.id DESC;

-- name: CreateImportedTaxDocument :one
INSERT INTO imported_tax_documents (imported_by_user_id, original_name, storage_path, content_type)
VALUES (?, ?, ?, ?)
RETURNING id;

-- name: GetImportedTaxDocumentByID :one
SELECT
  imported_tax_documents.id,
  imported_tax_documents.imported_by_user_id,
  users.display_name AS imported_by_name,
  imported_tax_documents.original_name,
  imported_tax_documents.storage_path,
  imported_tax_documents.content_type,
  imported_tax_documents.created_at
FROM imported_tax_documents
JOIN users ON users.id = imported_tax_documents.imported_by_user_id
WHERE imported_tax_documents.id = ?;

-- name: ListPlaintextUploadedFiles :many
SELECT id, original_name, storage_path
FROM uploaded_files
WHERE storage_path NOT LIKE '%.enc';

-- name: ListPlaintextImportedTaxDocuments :many
SELECT id, original_name, storage_path
FROM imported_tax_documents
WHERE storage_path NOT LIKE '%.enc';

-- name: UpdateUploadedFileStorage :exec
UPDATE uploaded_files
SET storage_path = ?, content_type = ?
WHERE id = ?;

-- name: UpdateImportedTaxDocumentStorage :exec
UPDATE imported_tax_documents
SET storage_path = ?, content_type = ?
WHERE id = ?;
