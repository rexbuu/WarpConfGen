# WarpConfGen

Modern FastAPI web app to generate Cloudflare WARP WireGuard configs with a premium UI and Myanmar language support.

## Features

- **Premium UI**: Glassmorphism design, warm color palette, and smooth micro-interactions.
- **Mobile Friendly**: Fully responsive design for both desktop and mobile.
- **Bilingual**: Friendly Myanmar language support with a language toggle (EN/MM).
- **Easy Instructions**: Built-in "How to Use" and "How to Connect" guides.
- **Supabase Integration**: Global generation counter stored in Supabase.
- **Secure**: Generates WireGuard key pairs and registrations locally.
- **Export Options**: Downloadable `.conf` and QR `.png` for easy import.
- **Endpoint Selection**:
  - Auto Select (High speed)
  - Choose from List
  - Custom Endpoint IP

## Tech Stack

- **Backend**: Python 3.12+, FastAPI, Uvicorn, Requests
- **Security**: PyNaCl (for key generation)
- **UI**: Vanilla HTML/CSS/JS, Lucide Icons, Google Fonts (Outfit, DM Mono)
- **Database**: Supabase (for global stats)

## Local Run

```bash
pip install -r requirements.txt
cp .env.example .env
python main.py
```

Open: `http://127.0.0.1:8000`

## Supabase Setup (Optional)

To enable the global generation counter:

1. Create a project on [Supabase](https://supabase.com).
2. Create a table named `stats`:
   - `id`: int (Primary Key, set to 1)
   - `total_generations`: int (Default: 0)
3. Create a Postgres function for atomic increments:
   ```sql
   CREATE OR REPLACE FUNCTION increment_gen_count()
   RETURNS void AS $$
   BEGIN
     UPDATE stats
     SET total_generations = total_generations + 1
     WHERE id = 1;
   END;
   $$ LANGUAGE plpgsql;
   ```
4. Add your `SUPABASE_URL` and `SUPABASE_KEY` to the `.env` file.

## Environment Variables

```dotenv
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_anon_key
STATS_FILE=warpgen_stats.json
```

## Vercel Deploy

This project is ready for Vercel deployment:

```bash
vercel --prod
```

## License

MIT Licensed. This project is provided for educational purposes.
