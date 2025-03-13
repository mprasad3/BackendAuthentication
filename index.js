const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookiesParser = require("cookie-parser");
const dotenv = require("dotenv").config();

// console.log("env data : ",process.env)
const app = express();

// middleware
app.use(express.json());
app.use(cookiesParser());
// database setup
const MONGO_URL = process.env.MONGO_URL;

try {
  mongoose
    .connect(MONGO_URL, { dbName: "BackendTask" })
    .then(() => {
      console.log("Database connected Successfully");
    })
    .catch((Err) => {
      console.log("Failed to connect Database", Err);
    });
} catch (err) {
  console.log("Database connection Error ", err);
}

// schema
const schema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

// database model
const User = mongoose.model("user", schema);

// all routes

// get method
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Welcome to Home page",
  });
});

// post method
app.get("/api/alluser", async (req, res) => {
  try {
    const userName = [];
    const AllUser = await User.find();

    for (const user of AllUser) {
      userName.push(user.name);
    }
    res.json({
      success: true,
      message: "All Users here ",
      UserList: userName,
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: "Internal server error",
    });
  }
});

// 01 Registration
app.post("/api/register", async (req, res) => {
  // get info from client ( name,email, password, confirm password)
  const { name, email, password, confirmPass } = req.body;
  try {
    // check whether email already exist in database or not
    const registeredUser = await User.findOne({ email: email });

    if (registeredUser) {
      return res.status(400).json({
        sucess: true,
        message: "User already Exist!",
      });
    }
    // check confirm password and password are same.
    if (password !== confirmPass) {
      return res.status(401).json({
        sucess: true,
        message: "confirm password and password are not same",
      });
    }
    // hash your password
    const hashedPassword = await bcrypt.hash(password, 10);

    // create user in database.
    await User.create({
      name: name,
      email: email,
      password: hashedPassword,
    })
      .then(() => {
        console.log("User registered !");
      })
      .catch(() => {
        console.log("Registration failed !");
      });

    // registration message
    return res.status(201).json({
      sucess: true,
      message: `${name} Registerd Successfully!`,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Failed to registration of new user",
    });
  }
});

// 02 login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // check the regstration in the database
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(400).json({
        success: true,
        message: "Email is not registered !",
      });
    }

    // password match
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({
        success: true,
        message: "Password Doesn't match!",
      });
    }
    // jwt generate
    const userId = user._id;
    const token = jwt.sign({ id: userId }, process.env.JWT_SECRET);

    res.status(200).cookie("token", token).json({
      success: true,
      message: "Logged in Successfully !",
    });
  } catch (err) {
    res.json({
      success: false,
      message: "Failed to Login !",
    });
  }
});

// authentication middleware
const Authentication = async (req, res, next) => {
  const { token } = req.cookies;

  if (!token) {
    return res.status(404).json({
      success: false,
      message: "Login first",
    });
  }

  const decode = jwt.verify(token, process.env.JWT_SECRET);
  req.user = await User.findById(decode.id);

  next();
};

// profile section
app.get("/api/profile", Authentication, (req, res) => {
  res.status(200).json({
    success: true,
    message: `Welcome  ${req.user?.name}`,
    email: req.user?.email,
  });
});

// 03 logout
app.get("/api/logout", (req, res) => {
  res.status(200).cookie("token", "").json({
    success: true,
    message: "logged out successfully !!",
    user: req.user,
  });
});

// Put method
app.put("/api/updateEmail", Authentication, async (req, res) => {
  // get the email from req.body;
  const { email, newEmail } = req.body;
  //check email if it is present in database //
  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(400).json({
      sucess: true,
      message: "Email not found !",
    });
  }
  //update email with new email

  const id = user.id;
  const updatedData = await User.findByIdAndUpdate(
    id,
    { email: newEmail },
    { new: true }
  );
  if (updatedData.email !== newEmail)
    return res
      .status(400)
      .json({ sucess: true, message: "Email is not updated" });

  // return message with update email
  res.status(200).json({
    success: true,
    message: `Your new email is ${newEmail}`,
  });
});

//update password (steps:enter the old password if it is correct then enter the new password and set)
app.put("/api/updatePassword", Authentication, async (req, res) => {
  const { password, newPassword } = req.body;

  // compare password with login password, whether it is corerct or not, if not then return messg : enter correct password
  const isMatch = await bcrypt.compare(password, req.user.password);
  if (!isMatch)
    return res
      .status(400)
      .json({ success: false, message: "Enter the correct old password" });

  const hashPassword = await bcrypt.hash(newPassword, 10);

  const id = req.user?.id;
  await User.findByIdAndUpdate(id, { password: hashPassword }, { new: true });

  res.status(200).cookie("token", "").json({
    success: true,
    message: `You have successfully update your password`,
  });
});

// delete method
app.delete("/api/deleteAccount", Authentication, async (req, res) => {
  const deletedAccount = await User.deleteOne({ _id: req.user.id });
  console.log("deleted Acccount ; ", deletedAccount);

  res.status(200).cookie("token", "").json({
    success: true,
    message: "Account deleted permanently !",
  });
});

app.listen(process.env.PORT, () => {
  console.log(`This server is running on port ${process.env.PORT}`);
});
