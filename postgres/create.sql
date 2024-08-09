CREATE TABLE Clients (
    id SERIAL PRIMARY KEY,
    nickname VARCHAR(255) UNIQUE,
    email VARCHAR(255) UNIQUE,
    ip VARCHAR(255),
    refreshtoken BYTEA
);

CREATE INDEX nick ON Clients (nickname);
CREATE INDEX email ON Clients (email);