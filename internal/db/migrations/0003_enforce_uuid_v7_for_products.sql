ALTER TABLE products
ADD CONSTRAINT products_id_uuid_v7_check
CHECK (substring(id::text FROM 15 FOR 1) = '7')
NOT VALID;
