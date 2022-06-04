require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const _ = require("lodash");
("use strict");
const nodemailer = require("nodemailer");

// my modules
const User = require("./mongoose_models/User"); // why this and not import

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

main().catch((err) => console.log(err));

async function main() {
  // await mongoose.connect(process.env.MONGODB_URI);
  await mongoose.connect(process.env.ATLAS_URI);
}

const app = express();

app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // app.use(bodyParser.json()) // to parse json request to js object, but now we this

/////////////////////////////////////////// REGISTER ROUTE ////////////////////////////////////////////////////

app.post("/register", async (req, res) => {
  // check whether a user with the requested email address already exists

  User.findOne({ email: req.body.email }, function (err, foundUser) {
    if (err) {
      console.log(err);
      res.status(400).send("We are unable to register the user");
    } else if (foundUser) {
      // User already exists
      res
        .status(400)
        .send("A user with this Email Address is already registered");
    } else {
      // create new User

      bcrypt.hash(
        req.body.password,
        saltRounds,
        function (err, hashedPassword) {
          const newUser = new User({
            email: req.body.email,
            password: hashedPassword,
          });

          newUser.save();
          res.status(200).send("User registered successfully");
        }
      );
    }
  }).clone(); // .clone() for multiple requests
});

///////////////////////////////////////// LOGIN ROUTE /////////////////////////////////////////////////

app.post("/login", async (req, res) => {
  await User.findOne({ email: req.body.email }, function (err, foundUser) {
    if (err) {
      // some error in finding
      console.log(err);
      res.status(400).send("We are unable to login the user");
    } else if (!foundUser) {
      // user not found
      console.log("No one found");
      res
        .status(400)
        .send("We are unable to find any user with these credentials");
    } else {
      // user with this email found, compare password
      bcrypt.compare(
        req.body.password,
        foundUser.password,
        function (err, result) {
          if (err) {
            // some error in comparing
            console.log(err);
            res.status(400).send("We are unable to login the user");
          } else if (!result) {
            res
              .status(400)
              .send("We are unable to find any user with these credentials");
          } else {
            // create a jwt token
            jwt.sign(
              { email: req.body.email },
              process.env.ACCESS_TOKEN_SECRET,
              function (err, token) {
                if (err) {
                  console.log(err);
                  res.status(400).send("We are unable to login the user");
                } else {
                  // console.log(token);
                  res.status(200).send({
                    token: token,
                    message: "User logged in successfully",
                  });
                }
              }
            );
          }
        }
      );
    }
  }).clone(); // .clone() for multiple requests
});

////////////////////////////////////////////////// POST ROUTE //////////////////////////////////////////////////

app.get("/posts", async (req, res) => {
  // console.log(req.headers);
  const token = _.split(req.headers.authorization, " ", 2)[1]; // removing the string "Bearer "
  // console.log(token);

  // verify a token symmetric
  jwt.verify(
    token,
    process.env.ACCESS_TOKEN_SECRET,
    function (err, decodedToken) {
      if (err) {
        // console.log(err);
        res.status(400).send("Invalid token");
      } else {
        res.status(200).send({ noOfPosts: 6, noOfUpVotes: 80 }); // dummy data to test
      }
    }
  );
});

///////////////////////////////////////////////// OTP ROUTE /////////////////////////////////////////////////////

app.post("/otp", async (req, res) => {
  // console.log("Your OTP is: 123456");

  const OTP = 100000 + Math.floor(Math.random() * 900000);
  const OTPText = OTP.toString();

  console.log(req.body.email);

  console.log(process.env.EMAIL);
  console.log(process.env.APP_PASSWORD);
  var transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL,
      pass: process.env.APP_PASSWORD, // app specific password
    },
  });

  var mailOptions = {
    from: `ApjTech Authentication System <${process.env.EMAIL}>`,
    to: req.body.email,
    subject: "Sending OTP using Node.js",
    text: `Your OTP is: ${OTPText}`,
  };

  await transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
      // client is waiting for a response
      res.send("Email sent successfully");
    }
  });
});

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Server is running on ${port}`);
});
