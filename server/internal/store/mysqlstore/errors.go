package mysqlstore

import (
	"errors"

	"github.com/go-sql-driver/mysql"
)

// isForeignKeyMissing reports MySQL error 1452 (child row references a missing parent),
// which here means the user row does not exist.
func isForeignKeyMissing(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == 1452
}
