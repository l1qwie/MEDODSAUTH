CREATE TABLE Clients (
    id SERIAL PRIMARY KEY,
    nickname VARCHAR(255) UNIQUE,
    email VARCHAR(255) UNIQUE,
    ip VARCHAR(255),
    refreshtoken BYTEA
);
