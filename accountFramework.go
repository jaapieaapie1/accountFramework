package accountFramework

import "database/sql"

type Instance struct {
	DBConnection *sql.DB
	JWTBase []byte
}

func NewInstance(dbConn *sql.DB, encryptionBase string) (*Instance, error) {
	instance := &Instance{
		DBConnection: dbConn,
		JWTBase: []byte(encryptionBase),
	}
	err := instance.PrepareDatabase()
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (i *Instance) PrepareDatabase() error {
	_, err := i.DBConnection.Exec(`create table if not exists user
(
    id       int auto_increment
        primary key,
    uuid     varchar(36) not null,
    username varchar(16) null,
    email    text        null,
    password text        not null,
    constraint user_email_uindex
        unique (email) using hash,
    constraint user_username_uindex
        unique (username),
    constraint user_uuid_uindex
        unique (uuid)
);`)

	return err
}
