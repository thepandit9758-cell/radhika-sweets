-- Radhika Sweets D1 Database Schema (SQLite)

CREATE TABLE IF NOT EXISTS menu_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  price INTEGER NOT NULL CHECK (price > 0),
  unit TEXT NOT NULL,
  img_key TEXT NOT NULL DEFAULT 'royal',
  description TEXT NOT NULL,
  badge TEXT DEFAULT 'Fresh',
  available INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  branch TEXT NOT NULL,
  order_type TEXT NOT NULL CHECK (order_type IN ('Dine-In', 'Pickup', 'Delivery')),
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  address TEXT NOT NULL,
  items_json TEXT NOT NULL,
  total_amount INTEGER NOT NULL CHECK (total_amount >= 0),
  status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Preparing', 'Ready', 'Completed')),
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_name TEXT NOT NULL,
  branch TEXT NOT NULL,
  stars INTEGER NOT NULL CHECK (stars BETWEEN 1 AND 5),
  comment TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Seed initial menu items
INSERT INTO menu_items (name, category, price, unit, img_key, description, badge, available) VALUES
('Silver-Leaf Kaju Katli', 'Desi Ghee Sweets', 540, '500g', 'kaju', 'Hand-rolled premium Goa cashews with edible chandi varq.', 'Bestseller', 1),
('Kesar Motichoor Ladoo', 'Desi Ghee Sweets', 320, '500g', 'royal', 'Fine boondi pearls slow-fried in pure desi ghee with Kashmiri saffron.', 'Pure Desi Ghee', 1),
('Saffron Matka Rasmalai', 'Bengali Sweets', 140, '2 Pcs', 'rasmalai', 'Soft chenna patties soaked in chilled saffron-pistachio rabri.', 'Chef Special', 1),
('Mathura Special Khasta Kachori', 'Namkeen & Chaat', 60, '2 Pcs Plate', 'chaat', 'Crispy flaky kachori served with spiced aloo sabzi & tamarind chutney.', 'Hot & Fresh', 1);
