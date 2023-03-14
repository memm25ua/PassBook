/*
Servidor
Hay que importar el driver de mongoDB para Go:

	go get go.mongodb.org/mongo-driver/mongo
	go get go.mongodb.org/mongo-driver/mongo/options
	go get go.mongodb.org/mongo-driver/bson
	go get golang.org/x/crypto/argon2
*/
package srv

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/argon2"
)

type DBUser struct {
	ID    primitive.ObjectID `bson:"_id"`
	Name  string             `bson:"name"`
	Hash  []byte             `bson:"hash"`
	Salt  []byte             `bson:"salt"`
	Token []byte             `bson:"token"`
	Seen  time.Time          `bson:"seen"`
}

type user struct {
	Name  string    // nombre de usuario
	Hash  []byte    // hash de la contraseña
	Salt  []byte    // sal para el hash
	Token []byte    // token de sesión
	Seen  time.Time // última vez que fue visto
}

var keyFile string = "C:/Users/Madani/Desktop/SDS/PassBook/servidor/srv/X509-cert-dbkey.pem" // ruta al certificado de la base de datos
var uri string = "mongodb+srv://passbook.b6ormcu.mongodb.net/?authMechanism=MONGODB-X509&authSource=%24external&tlsCertificateKeyFile=" + keyFile + "&tls=true"
var serverAPIOptions = options.ServerAPI(options.ServerAPIVersion1)
var clientOptions = options.Client().
	ApplyURI(uri).
	SetServerAPIOptions(serverAPIOptions)

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func Run() {
	http.HandleFunc("/", handler) // asignamos un handler global

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		fmt.Println("register")
		ok := userExists(req.Form.Get("user")) // ¿existe ya el usuario?

		if ok {
			response(w, false, "Usuario ya registrado", nil)
			return
		}

		u := user{}
		u.Name = req.Form.Get("user")    // nombre de usuario
		password := req.Form.Get("pass") // contraseña (keyLogin)

		//Utiliza argon2id
		u.Salt = make([]byte, 16) // sal (16 bytes == 128 bits)
		u.Hash = argon2.IDKey([]byte(password), u.Salt, 1, 64*1024, 4, 32)
		u.Seen = time.Now()        // asignamos tiempo de login
		u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
		rand.Read(u.Token)         // el token es aleatorio

		if registerUser(u) {
			response(w, true, "Usuario registrado", u.Token)
		} else {
			response(w, false, "Error al registrar usuario", nil)
		}

	case "login": // ** login
		ok := userExists(req.Form.Get("user")) // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}

		ok, u := loginUser(req.Form.Get("user"), req.Form.Get("pass")) // comprobamos credenciales
		if !ok {
			response(w, false, "Credenciales inválidas", nil)

		} else {
			u.Seen = time.Now()        // asignamos tiempo de login
			u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
			rand.Read(u.Token)         // el token es aleatorio
			response(w, true, "Credenciales válidas", u.Token)
		}

	default:
		response(w, false, "Comando no implementado", nil)
	}

}

// respuesta del servidor
// (empieza con mayúscula ya que se utiliza en el cliente también)
// (los variables empiezan con mayúscula para que sean consideradas en el encoding)
type Resp struct {
	Ok    bool   // true -> correcto, false -> error
	Msg   string // mensaje adicional
	Token []byte // token de sesión para utilizar por el cliente
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string, token []byte) {
	r := Resp{Ok: ok, Msg: msg, Token: token} // formateamos respuesta
	rJSON, err := json.Marshal(&r)            // codificamos en JSON
	chk(err)                                  // comprobamos error
	w.Write(rJSON)                            // escribimos el JSON resultante
}

// función para comprobar si un usuario existe
func userExists(name string) bool {
	client, err := mongo.Connect(context.Background(), clientOptions)
	chk(err)

	collection := client.Database("passbook").Collection("users")
	filter := bson.D{{"name", name}}

	var result DBUser
	err = collection.FindOne(context.Background(), filter).Decode(&result)

	return err == nil
}

// función para registrar un usuario
func registerUser(u user) bool {
	client, err := mongo.Connect(context.Background(), clientOptions)
	chk(err)

	collection := client.Database("PassBook").Collection("users")
	insertResult, err := collection.InsertOne(context.Background(), u)
	_ = insertResult
	fmt.Println(err)
	return err == nil
}

// función para comprobar credenciales de un usuario
func loginUser(name, password string) (bool, user) {
	client, err := mongo.Connect(context.Background(), clientOptions)
	chk(err)

	collection := client.Database("passbook").Collection("users")
	filter := bson.D{{"Name", name}}

	var result DBUser
	err = collection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		return false, user{}
	}

	//Utiliza argon2id
	hash := argon2.IDKey([]byte(password), result.Salt, 1, 64*1024, 4, 32)
	if bytes.Compare(hash, result.Hash) == 0 {
		return true, user{Name: name, Hash: hash, Salt: result.Salt}
	}
	return false, user{}

}
