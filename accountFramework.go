package accountFramework

import (
	"database/sql"
	"github.com/bwmarrin/snowflake"
)

type Instance struct {
	DBConnection  *sql.DB
	JWTBase       []byte
	snowFlakeNode *snowflake.Node
}

func NewInstance(dbConn *sql.DB, encryptionBase string, nodeId int64) (*Instance, error) {
	node, err := snowflake.NewNode(nodeId)

	if err != nil {
		return nil, err
	}

	instance := &Instance{
		DBConnection:  dbConn,
		JWTBase:       []byte(encryptionBase),
		snowFlakeNode: node,
	}
	err = instance.PrepareDatabase()
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (i *Instance) PrepareDatabase() error {
	_, err := i.DBConnection.Exec(`create table if not exists user
(
    id       BIGINT SIGNED
        primary key,
    username varchar(16) null,
    email    varchar(255)        null,
    password text        not null,
    constraint user_email_uindex
        unique (email) using hash,
    constraint user_username_uindex
        unique (username)
);`)

	return err
}
