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
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/argon2"
)

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// ejemplo de tipo para un usuario
type user struct {
	Name  string            // nombre de usuario
	Hash  string            // hash de la contraseña
	Token []byte            // token de sesión
	Seen  time.Time         // última vez que fue visto
	Data  map[string]string // datos adicionales del usuario
}

var clientOptions *options.ClientOptions

func Run() {
	uri := "mongodb+srv://passbook.b6ormcu.mongodb.net/?authSource=%24external&authMechanism=MONGODB-X509&retryWrites=true&w=majority&tlsCertificateKeyFile=./X509-cert-dbkey.pem"
	serverAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPIOptions)

	http.HandleFunc("/", handler) // asignamos un handler global

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		ok := userExists(req.Form.Get("user")) // ¿existe ya el usuario?

		if ok {
			response(w, false, "Usuario ya registrado", nil)
			return
		}

		u := user{}
		u.Name = req.Form.Get("user")              // nombre
		u.Data = make(map[string]string)           // reservamos mapa de datos de usuario
		u.Data["private"] = req.Form.Get("prikey") // clave privada
		u.Data["public"] = req.Form.Get("pubkey")  // clave pública
		password := req.Form.Get("pass")           // contraseña (keyLogin)

		// "hasheamos" la contraseña con scrypt (argon2 es mejor)
		//Utiliza argon2id
		u.Hash, _ = argon2.CreateHash(password, argon2.defaultParams)
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
		if ok {
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

func userExists(user string) bool {
	var result bson.M
	err := clientOptions.Database("PassBook").Collection("users").FindOne(context.Background(), bson.M{"name": user}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false
		}
	}
	return true
}

func registerUser(usuario user) bool {
	_, err := clientOptions.Database("PassBook").Collection("users").InsertOne(context.Background(), usuario).SetBypassDocumentValidation(true)
	if err != nil {
		return false
	}
	return true
}

func loginUser(usuario string, password string) (bool, j) {
	var result bson.M
	err := clientOptions.Database("PassBook").Collection("users").FindOne(context.Background(), bson.M{"name": user}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
	}
	return argon2.CompareHashAndPassword(result["hash"].(string), password), result

}
