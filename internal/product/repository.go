package product

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) List(ctx context.Context) ([]Product, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, title, description, price, image_url, created_at, updated_at
		FROM products
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query products: %w", err)
	}
	defer rows.Close()

	products := make([]Product, 0)
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Title, &p.Description, &p.Price, &p.ImageURL, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan product: %w", err)
		}
		products = append(products, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate products: %w", err)
	}

	return products, nil
}

func (r *Repository) Create(ctx context.Context, input ProductInput) (Product, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return Product{}, fmt.Errorf("generate uuid v7: %w", err)
	}

	now := time.Now().UTC()
	p := Product{
		ID:          id.String(),
		Title:       input.Title,
		Description: input.Description,
		Price:       input.Price,
		ImageURL:    input.ImageURL,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO products (id, title, description, price, image_url, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, p.ID, p.Title, p.Description, p.Price, p.ImageURL, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return Product{}, fmt.Errorf("insert product: %w", err)
	}

	return p, nil
}

func (r *Repository) Update(ctx context.Context, id string, input ProductInput) (Product, error) {
	var p Product
	p.UpdatedAt = time.Now().UTC()

	err := r.db.QueryRowContext(ctx, `
		UPDATE products
		SET title = $2, description = $3, price = $4, image_url = $5, updated_at = $6
		WHERE id = $1
		RETURNING id, title, description, price, image_url, created_at, updated_at
	`, id, input.Title, input.Description, input.Price, input.ImageURL, p.UpdatedAt).
		Scan(&p.ID, &p.Title, &p.Description, &p.Price, &p.ImageURL, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return Product{}, err
		}
		return Product{}, fmt.Errorf("update product: %w", err)
	}

	return p, nil
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM products WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete product: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if affected == 0 {
		return sql.ErrNoRows
	}

	return nil
}
