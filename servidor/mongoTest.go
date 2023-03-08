package srv

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DBUser struct {
	ID    primitive.ObjectID `bson:"_id"`
	Name  string             `bson:"name"`
	Hash  string             `bson:"hash"`
	Token []byte             `bson:"token"`
	Seen  time.Time          `bson:"seen"`
}

type user struct {
	Name  string    // nombre de usuario
	Hash  string    // hash de la contraseña
	Token []byte    // token de sesión
	Seen  time.Time // última vez que fue visto
}

var uri string = "mongodb+srv://passbook.b6ormcu.mongodb.net/?authMechanism=MONGODB-X509&authSource=%24external&tlsCertificateKeyFile=X509-cert-dbkey.pem&tls=true"
var serverAPIOptions = options.ServerAPI(options.ServerAPIVersion1)
var clientOptions = options.Client().
	ApplyURI(uri).
	SetServerAPIOptions(serverAPIOptions)

func main() {
	ctx := context.TODO()
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	collection := client.Database("PassBook").Collection("users")
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var result DBUser
		err := cursor.Decode(&result)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(result)
	}
}
