CREATE TABLE history (
  id INTEGER,
  person_id INTEGER,
  reason TEXT,
  shares INTEGER,
  symbol TEXT,
  time_transacted TEXT,
  FOREIGN KEY(person_id) REFERENCES users(id)
  PRIMARY KEY(id)
);

CREATE TABLE portfolio (
  id INTEGER,
  person_id INTEGER,
  shares INTEGER,
  symbol TEXT,
  FOREIGN KEY(person_id) REFERENCES users(id),
  PRIMARY KEY(id)
);


