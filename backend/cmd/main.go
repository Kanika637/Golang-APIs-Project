package main

import (
	"context"
	"time"
	"log"
	"net/http"
	"github.com/gorilla/mux"
	"encoding/json"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
	"github.com/dgrijalva/jwt-go"
    "fmt"
  
    
   
)
var SECRET_KEY = []byte("gosecretkey")

//user data
type User struct{
    Username string          `json:"username" bson:"username"`
	Password string          `json:"password" bson:"password"`
}

// for the jwt token

type Claims struct{
    Username string `json:"username"`
    jwt.StandardClaims
}

var client *mongo.Client

//hashing the password

func getHash(pwd []byte) string {
    hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
    if err != nil {
        log.Println(err)
    }
    return string(hash)
}


//adding a user

func createUser(response http.ResponseWriter, request *http.Request){
	response.Header().Set("Content-Type","application/json")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	user.Password = getHash([]byte(user.Password))
	collection := client.Database("houseware").Collection("users")
	ctx,_ := context.WithTimeout(context.Background(), 10*time.Second)
	result,_ := collection.InsertOne(ctx,user)
	json.NewEncoder(response).Encode(result)
}


//logging in the user

func userLogin(w http.ResponseWriter, request *http.Request){
    w.Header().Set("Content-Type","application/json")
    var user User
    var dbUser User
    json.NewDecoder(request.Body).Decode(&user)
    collection:= client.Database("houseware").Collection("users")
    ctx,_ := context.WithTimeout(context.Background(),10*time.Second)
    err:= collection.FindOne(ctx, bson.M{"username":user.Username}).Decode(&dbUser)
  
    if err!=nil{
        w.WriteHeader(http.StatusInternalServerError)
        w.Write([]byte(`{"message":"`+err.Error()+`"}`))
        return
    }
    userPass:= []byte(user.Password)
    dbPass:= []byte(dbUser.Password)
  
    passErr:= bcrypt.CompareHashAndPassword(dbPass, userPass)
  
    if passErr != nil{
        log.Println(passErr)
        w.Write([]byte(`{"response":"Wrong Password!"}`))
        return
    }

    expirationTime := time.Now().Add(time.Minute * 2)

	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(SECRET_KEY)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

   

	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})

        w.Write([]byte(`{"token":"`+tokenString+`"}`))
	
}


// checking the authorization by matching the token

func authorize(w http.ResponseWriter, r *http.Request){
    cookie, err := r.Cookie("token")
    if err !=nil{
        if err == http.ErrNoCookie{
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
        w.WriteHeader(http.StatusBadRequest)
        return
    }
        tokenStr :=cookie.Value
        claims :=&Claims{}

        tkn, err :=jwt.ParseWithClaims(tokenStr, claims,
        func (t*jwt.Token) (interface{}, error){
           return SECRET_KEY, nil
        })

        if err !=nil {
            if err == jwt.ErrSignatureInvalid{
                w.WriteHeader(http.StatusUnauthorized)
                return
            }
            w.WriteHeader(http.StatusBadRequest)
            return
        }

        if !tkn.Valid{
            w.WriteHeader(http.StatusUnauthorized)
            return
        }
        w.Write([] byte(fmt.Sprint("hello, %s", claims.Username)))
    }


    // refresh the token
  
  func refresh_token(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return SECRET_KEY, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
	// 	w.WriteHeader(http.StatusBadRequest)
	// 	return
	// }

	expirationTime := time.Now().Add(time.Minute * 5)

	claims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(SECRET_KEY)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w,
		&http.Cookie{
			Name:    "refresh_token",
			Value:   tokenString,
			Expires: expirationTime,
		})


}

    // list all the users

  func showAll(response http.ResponseWriter, request *http.Request){
    response.Header().Set("Content-Type","application/json")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	collection := client.Database("houseware").Collection("users")
	ctx,_ := context.WithTimeout(context.Background(), 10*time.Second)
    cursor, err := collection.Find(ctx, bson.M{})
    if err != nil {
        log.Fatal(err)
    }
    var episodes []bson.M
    if err = cursor.All(ctx, &episodes); err != nil {
        log.Fatal(err)
    }
    json.NewEncoder(response).Encode(episodes)
    log.Println(episodes)
  }
    

    func main(){
	log.Println("Starting the application")

	router:= mux.NewRouter()
	ctx,_ := context.WithTimeout(context.Background(), 10*time.Second)
	client,_= mongo.Connect(ctx,options.Client().ApplyURI("mongodb://localhost:27017"))

	router.HandleFunc("/user/login",userLogin).Methods("POST")
	router.HandleFunc("/user/create_user",createUser).Methods("POST")
    // router.HandleFunc("/user/:username",deleteRecord).Methods("DELETE")
    router.HandleFunc("/user/authorize",authorize).Methods("POST")
    router.HandleFunc("/user/all",showAll).Methods("GET")
    router.HandleFunc("/user/token_refresh",refresh_token).Methods("POST")
    log.Fatal(http.ListenAndServe("localhost:8000", router))

}