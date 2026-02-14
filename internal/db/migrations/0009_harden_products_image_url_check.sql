ALTER TABLE products
DROP CONSTRAINT IF EXISTS products_image_url_http_check;

ALTER TABLE products
ADD CONSTRAINT products_image_url_http_check
CHECK (
    image_url ~ '^[A-Za-z0-9\-._~:/?#\[\]@!$&''()*+,;=%]+$'
    AND image_url ~* '^https?://'
    AND image_url !~ '[[:space:]]'
);
