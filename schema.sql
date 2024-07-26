DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS userdata;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS blacklist;
DROP TABLE IF EXISTS oauth;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    uniqueid TEXT NOT NULL,
    migrated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE userdata (
    creator INTEGER NOT NULL,
    appId TEXT NOT NULL,
    secret TEXT NOT NULL
);

CREATE TABLE sessions (
    sessionid INTEGER PRIMARY KEY AUTOINCREMENT,
    session TEXT NOT NULL,
    id INTEGER NOT NULL,
    device TEXT NOT NULL DEFAULT '?'
);

CREATE TABLE blacklist (
    openid TEXT NOT NULL,
    blacklisted BOOLEAN NOT NULL DEFAULT true,
    token TEXT NOT NULL
);

CREATE TABLE oauth (
    appId TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL,
    creator INTEGER NOT NULL,
    redirectUri TEXT NOT NULL,
    name TEXT NOT NULL,
    keyShareUri TEXT NOT NULL DEFAULT 'none',
    scopes TEXT NOT NULL DEFAULT '["openid"]'
)
