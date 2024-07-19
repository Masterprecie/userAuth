const express = require("express");
const mongoose = require("mongoose");
require("dotenv").config();
const authRoute = require("./routesAndControllers/authenticationRoutes");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

//Connect to MongoDB

mongoose
  .connect(process.env.MONGODB_URL)
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.log("Failed to connect to MongoDB", err);
  });

app.use("/auth", authRoute);

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});
