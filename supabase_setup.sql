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

-- 4. Create the v2_subscriptions table for personal links
-- This stores the latest generated config for a specific ID.
CREATE TABLE IF NOT EXISTS v2_subscriptions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    config_uri text NOT NULL,
    updated_at timestamptz DEFAULT now()
);

-- 5. Create a function to update or create a subscription atomically
CREATE OR REPLACE FUNCTION update_v2_subscription(p_id uuid, p_uri text)
RETURNS void AS $$
BEGIN
    INSERT INTO v2_subscriptions (id, config_uri, updated_at)
    VALUES (p_id, p_uri, now())
    ON CONFLICT (id) DO UPDATE
    SET config_uri = EXCLUDED.config_uri,
        updated_at = EXCLUDED.updated_at;
END;
$$ LANGUAGE plpgsql;
