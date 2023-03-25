package main

import (
	"context"
	"time"
	"log"
	"net/http"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
	"github.com/dgrijalva/jwt-go"
    "fmt"
    myTypes "github.com/HousewareHQ/backend-engineering-octernship/models"
	
   
)


// accessing the type struct

type User= myTypes.User
type Claims= myTypes.Claims

var SECRET_KEY = []byte("gosecretkey")
var client *mongo.Client

func GetHash(pwd []byte) string {
    hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
    if err != nil {
        log.Println(err)
    }
    return string(hash)
}

//adding a user

func CreateUser(response http.ResponseWriter, request *http.Request){
	response.Header().Set("Content-Type","application/json")
	
    var user User
	json.NewDecoder(request.Body).Decode(&user)
	user.Password = GetHash([]byte(user.Password))
	collection := client.Database("houseware").Collection("users")
	ctx,_ := context.WithTimeout(context.Background(), 10*time.Second)
	result,_ := collection.InsertOne(ctx,user)
	json.NewEncoder(response).Encode(result)
}


//logging in the user

func UserLogin(w http.ResponseWriter, request *http.Request){
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

    //this is the expiration time i.e. 60 mins
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

func Authorize(w http.ResponseWriter, r *http.Request){
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
        w.Write([] byte(fmt.Sprint("Hello,", claims.Username)))
    }


    // refresh the token
  
  func Refresh_token(w http.ResponseWriter, r *http.Request) {
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

    //when 30 seconds will be remaining for the token to get expire, we will refresh it

	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

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

//delete a user

func Delete_user(response http.ResponseWriter, request *http.Request){

    vars := mux.Vars(request)
    username := vars["username"]
    response.Header().Set("Content-Type","application/json")
	var user User
    json.NewDecoder(request.Body).Decode(&user)
    
    collection := client.Database("houseware").Collection("users")
    filter := bson.M{"username": username}

    deleteCount, err := collection.DeleteOne(context.Background(), filter)

if err !=nil{
    log.Fatal(err)
}
json.NewEncoder(response).Encode(deleteCount)
    
}

    // list all the users

  func ShowAll(response http.ResponseWriter, request *http.Request){
    response.Header().Set("Content-Type","application/json")
	var user User
	json.NewDecoder(request.Body).Decode(&user)
	collection := client.Database("houseware").Collection("users")
	ctx,_ := context.WithTimeout(context.Background(), 10*time.Second)
    cursor, err := collection.Find(ctx, bson.M{})
    if err != nil {
        log.Fatal(err)
    }
    var accounts []bson.M
    if err = cursor.All(ctx, &accounts); err != nil {
        log.Fatal(err)
    }
    json.NewEncoder(response).Encode(accounts)
    log.Println(accounts)
  }

  // deleting the old cookie

  func Logout(w http.ResponseWriter, r *http.Request) {

    c := http.Cookie{
        Name:   "token",
        MaxAge: -1}
    http.SetCookie(w, &c)

    w.Write([]byte("Old cookie deleted. Logged out!\n"))
}
    
    func main(){
	

    
	router:= mux.NewRouter()
    
	ctx,_ := context.WithTimeout(context.Background(), 10*time.Second)
	client,_= mongo.Connect(ctx,options.Client().ApplyURI("mongodb://localhost:27017"))

    log.Println("Starting the application")
	router.HandleFunc("/user/create_user",CreateUser).Methods("POST")
    router.HandleFunc("/user/login",UserLogin).Methods("POST")
    router.HandleFunc("/user/{username}",Delete_user).Methods("DELETE")
    router.HandleFunc("/user/authorize",Authorize).Methods("POST")
    router.HandleFunc("/user/all",ShowAll).Methods("GET")
    router.HandleFunc("/user/token_refresh",Refresh_token).Methods("POST")
    router.HandleFunc("/user/logout",Logout).Methods("POST")

    log.Fatal(http.ListenAndServe("localhost:8000", router))

}