package main

import (
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"os"

	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	"learn/todo"
	"learn/todo/pkg/handler"
	"learn/todo/pkg/repository"
	"learn/todo/pkg/service"
)

func main() {
	logrus.SetFormatter(new(logrus.JSONFormatter))

	if err := initConfigs(); err != nil {
		logrus.Fatalf("error initializing configs %s", err.Error())
	}

	if err := godotenv.Load(); err != nil {
		logrus.Fatalf("error loading env variables: %s", err.Error())
	}
	db, err := repository.NewPostgresDB(repository.Config{
		Host:     viper.GetString("db.host"),
		Port:     viper.GetString("db.port"),
		Username: viper.GetString("db.username"),
		Password: os.Getenv("DB_PASSWORD"),
		DbName:   viper.GetString("db.dbname"),
		SSLMode:  viper.GetString("db.sslMode"),
	})
	if err != nil {
		logrus.Fatalf("failed to initialize db: %s", err.Error())
	}
	repos := repository.NewRepository(db)
	services := service.NewService(repos)
	handlers := handler.NewHandler(services)
	srv := new(todo.Server)
	if err := srv.Run(viper.GetString("port"), handlers.InitRoutes()); err != nil {
		logrus.Fatalf("error occurced while running http server: %s", err.Error())
	}

}

func initConfigs() error {
	viper.AddConfigPath("configs")
	viper.SetConfigName("config")
	return viper.ReadInConfig()
}
