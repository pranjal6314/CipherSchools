const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const cors = require("cors");
const PORT = 4000;
const mongoose = require("mongoose");
app.use(cors());
app.use(express.json());
const Schema = mongoose.Schema;
const secret = "your_jwt_secret";

const detailSchema = new Schema({
  firstname: {
    type: String,
  },
  lastname: {
    type: String,
  },
  age: {
    type: Number,
  },
  email: {
    type: String,
  },
  phone_number: {
    type: String,
  },
  password: {
    type: String,
  },
});
const Users = mongoose.model("Users", detailSchema);

app.post("/signup", async (req, res) => {
  try {
    const { firstname, lastname, age, email, phone_number, password } =
      req.body;

    // Generate a salt for the password hashing function
    const salt = await bcrypt.genSalt(10);

    // Hash the password with the salt
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create a new user with the hashed password
    const newUser = new Users({
      firstname: firstname,
      lastname: lastname,
      age: age,
      email: email,
      phone_number: phone_number,
      password: hashedPassword,
    });

    // Save the new user to the database
    await newUser.save();

    res.status(201).send("User created successfully");
  } catch (error) {
    console.log(`Error creating user: ${error}`);
    res.status(500).send("Error creating user");
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await Users.findOne({ email: email });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    console.log(user.password);

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign({ userId: user._id }, secret);
    res.status(200).json({ token: token });
  } catch (error) {
    console.log(`Error logging in user: ${error}`);
    res.status(500).send("Error logging in user");
  }
});

app.put("/users", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader;

    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const decodedToken = jwt.verify(token, secret);

    const userId = decodedToken.userId;
    console.log(userId);
    const { firstname, lastname, age, email, phone_number } = req.body;
    const user = await Users.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    user.firstname = firstname || user.firstname;
    user.lastname = lastname || user.lastname;
    user.age = age || user.age;
    user.email = email || user.email;
    user.phone_number = phone_number || user.phone_number;

    const updatedUser = await user.save();
    res.status(200).json(updatedUser);
  } catch (error) {
    console.log(`Error updating user profile: ${error}`);
    res.status(500).send("Error updating user profile");
  }
});

app.put("/users/:id/interests", async (req, res) => {
  const { interests } = req.body;
  const { id } = req.params;

  try {
    const user = await Users.findById(id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.interests = interests;

    const updatedUser = await user.save();
    return res.json(updatedUser);
  } catch (error) {
    console.log(`Error updating user interests: ${error}`);
    return res.status(500).json({ error: "Error updating user interests" });
  }
});

app.get("/users/:id/followers", async (req, res) => {
  const { id } = req.params;
  const { page = 1, limit = 10 } = req.query;

  try {
    const user = await Users.findById(id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const count = user.followers.length;

    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;
    const followers = user.followers.slice(startIndex, endIndex);

    return res.json({
      page,
      limit,
      totalPages: Math.ceil(count / limit),
      totalFollowers: count,
      followers,
    });
  } catch (error) {
    console.log(`Error fetching followers: ${error}`);
    return res.status(500).json({ error: "Error fetching followers" });
  }
});

mongoose
  .connect("mongodb://127.0.0.1:27017/s", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Database connected successfully");
  })
  .catch((err) => {
    console.log(`Database connection error: ${err}`);
  });

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
