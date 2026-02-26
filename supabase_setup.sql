-- WarpGen Supabase Setup Script
-- Run this in your Supabase SQL Editor to enable the global generation counter.

-- 1. Create the stats table
CREATE TABLE IF NOT EXISTS stats (
  id int PRIMARY KEY,
  total_generations int DEFAULT 0
);

-- 2. Insert the initial starting row (if it doesn't exist)
INSERT INTO stats (id, total_generations) 
VALUES (1, 0) 
ON CONFLICT (id) DO NOTHING;

-- 3. Create a secure function for the app to increment the count
-- This allows the Python script to increment the count atomically.
CREATE OR REPLACE FUNCTION increment_gen_count()
RETURNS void AS $$
BEGIN
  UPDATE stats
  SET total_generations = total_generations + 1
  WHERE id = 1;
END;
$$ LANGUAGE plpgsql;
