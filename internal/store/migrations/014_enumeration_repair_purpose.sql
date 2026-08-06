ALTER TABLE enumeration_shards
ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'primary';

ALTER TABLE enumeration_shards
DROP CONSTRAINT IF EXISTS enumeration_shards_purpose_check;

ALTER TABLE enumeration_shards
ADD CONSTRAINT enumeration_shards_purpose_check
CHECK (purpose IN ('primary', 'repair')) NOT VALID;
