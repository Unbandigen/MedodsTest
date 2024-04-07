package main

import (
	//"encoding/json"

	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var SecretKey = []byte("secret_key")

type User struct {
	ID       string `json:"id"`
	NAME     string `json:"name"`
	RefToken string `json:"refToken"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// пользователи, проверка на их существование, генерация access токена, refresh токена
func GetJWThandler(w http.ResponseWriter, r *http.Request) {

	// Подключение к Mongo
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	collection := client.Database("mongo").Collection("users")

	userGUID := r.URL.Query().Get("GUID")
	if userGUID == "" {
		w.Write([]byte("User ID is required"))
		return
	}

	Search := func(collection *mongo.Collection, userGUID string) (User, error) {
		ctx := context.Background()

		filter := bson.M{"guid": userGUID}
		var user User
		err := collection.FindOne(ctx, filter).Decode(&user)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return User{}, errors.New("User not found")
			}
			return User{}, err
		}

		return user, nil
	}

	_, err = Search(collection, userGUID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			w.Write([]byte("User not found"))
			return
		}
		w.Write([]byte("Error searching for user"))
		return
	}

	//Генерация уникального ключа для связки refresh и access токенов.
	UniqueKey := uuid.New()

	//Генерация JWT токена
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["userID"] = userGUID
	claims["key"] = UniqueKey
	claims["exp"] = time.Now().Add(time.Minute * 1).Unix()
	AccessToken, err := token.SignedString(SecretKey)

	//Генерация Refresh токена
	token2 := jwt.New(jwt.SigningMethodHS512)
	claims = token2.Claims.(jwt.MapClaims)
	claims["key"] = UniqueKey
	claims["exp"] = time.Now().Add(time.Minute * 5).Unix()
	RefreshToken, err := token2.SignedString(SecretKey)

	tokens := Tokens{
		AccessToken:  AccessToken,
		RefreshToken: RefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokens)

	// Хешируем refreshToken с использованием SHA-512
	l := RefreshToken
	refreshTokenBytes := []byte(l)
	hash := sha512.New()
	hash.Write(refreshTokenBytes)
	hashRefreshToken := hex.EncodeToString(hash.Sum(nil))

	//обновление рефреш токена пользователей
	filter := bson.M{"guid": userGUID}
	update := bson.M{
		"$set": bson.M{
			"refreshToken": hashRefreshToken,
		},
	}
	_, err = collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Пользователь успешно обновлен.")
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	// В запрос кладем полученные из прошлого хендлера access и refresh
	accessToken := r.URL.Query().Get("accessToken")
	refreshToken := r.URL.Query().Get("refreshToken")
	//если access или refresh не пришли, то возвращаем ошибку
	if accessToken == "" || refreshToken == "" {
		w.Write([]byte("Access token and refresh token are required"))
		return
	}
	//расшифровка ключей и проверка на совпадение ключей
	check, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(""), nil
	})
	claims, ok := check.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Ошибка")
		return
	}
	key, ok := claims["key"].(string)
	if !ok {
		fmt.Println("Ключ не найден")
		return
	}
	firstKey := key
	check, err = jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(""), nil
	})
	claims, ok = check.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Ошибка")
		return
	}
	key, ok = claims["key"].(string)
	if !ok {
		fmt.Println("Ключ не найден")
		return
	}
	secondKey := key
	if firstKey != secondKey {
		w.Write([]byte("Ключи токенов не совпадают"))
		return
	}

	//хешируем refreshToken, так как в БД токены тоже хешированы
	l := refreshToken
	refreshTokenBytes := []byte(l)
	hash := sha512.New()
	hash.Write(refreshTokenBytes)
	hashRefreshToken := hex.EncodeToString(hash.Sum(nil))

	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	//ищем нужного пользователя по рефреш токену в mongo
	collection := client.Database("mongo").Collection("users")
	filter := bson.M{"refreshToken": hashRefreshToken}
	var user User
	err = collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			w.Write([]byte("Пользователь не найден"))
			return
		}
		w.Write([]byte("Ошибка поиска пользователя"))
		return
	}

	//генерируем новые токены и обновляем рефреш токен в mongo

	UniqueKey := uuid.New()
	token := jwt.New(jwt.SigningMethodHS512)
	claims = token.Claims.(jwt.MapClaims)
	claims["userID"] = user.ID
	claims["key"] = UniqueKey
	claims["exp"] = time.Now().Add(time.Minute * 1).Unix()
	newAccessToken, err := token.SignedString(SecretKey)
	if err != nil {
		w.Write([]byte("Ошибка в генерации нового access токена"))
		return
	}
	refreshClaims := jwt.MapClaims{
		"key": UniqueKey,
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	}
	RefreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, refreshClaims)
	newRefreshToken, err := RefreshToken.SignedString(SecretKey)
	if err != nil {
		w.Write([]byte("Ошибка в генерации нового refresh токена"))
		return
	}
	tokens := Tokens{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokens)
	log.Println("Новый токен для пользователя успешно сгенерирован и перезаписан.")

	// Хешируем refreshToken с использованием SHA-512, чтобы перезаписать его в БД
	//для начала предстоит преобразовать refreshToken в массив байтов, а потом в хеш
	m := newRefreshToken
	RefreshTokenBytes := []byte(m)
	hash = sha512.New()
	hash.Write(RefreshTokenBytes)
	HashRefreshToken := hex.EncodeToString(hash.Sum(nil))

	//обновление рефреш токена пользователей
	filter = bson.M{"refreshToken": hashRefreshToken}
	update := bson.M{
		"$set": bson.M{
			"refreshToken": HashRefreshToken,
		},
	}
	_, err = collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/get-token", GetJWThandler)
	http.HandleFunc("/refresh", RefreshHandler)
	http.ListenAndServe(":8080", nil)
}
