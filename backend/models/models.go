package model
import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"github.com/dgrijalva/jwt-go"
)

//user data
type User struct{
    Id       primitive.ObjectID `bson:"_id,omitempty"`
    Username string             `json:"username" bson:"username"`
	Password string             `json:"password" bson:"password"`
    
}

// for the jwt token

type Claims struct{
    Username string `json:"username"`
    jwt.StandardClaims
}