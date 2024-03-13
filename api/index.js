const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const morgan = require("morgan");

app.use(express.json());
app.use(morgan("common"));

// store users in a list
const users = [
  {
    id: 1,
    username: "john",
    password: "John0908",
    isAdmin: true,
  },
  {
    id: 2,
    username: "jane",
    password: "Jane0908",
    isAdmin: false,
  },
];

// store refresh token
let refreshTokens = [];

// refresh token {route}
app.post("/api/refresh", (req, res) => {
  // take the refresh token from the user
  const refreshToken = req.body.token;

  // send error if there is no token or it's invalid
  if (!refreshToken) return res.status(401).json("You are not authenticated");
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("Refresh token is not valid");
  }
  jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
});

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
    expiresIn: "15m",
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshSecretKey");
};

// login route
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    // Generate access token
    const accessToken = generateAccessToken(user);
    const refereshToken = generateRefreshToken(user);
    refreshTokens.push(refereshToken);

    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refereshToken,
    });
  } else {
    res.status(400).json("Incorrect username or password");
  }
});

// verify token
const verify = (req, res, next) => {
  console.log("Headers received:", req.headers);
  const authHeader = req.headers.authorization;
  console.log("Authorization headers:", authHeader);
  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid");
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated!");
  }
};

// delete a user {route}
app.delete("/api/users/:userId", verify, (req, res) => {
  req.params.userId = parseInt(req.params.userId);
  if (req.user.isAdmin || req.user.id === req.params.userId) {
    res.status(200).json("User has been deleted successfully!");
  } else {
    res.status(403).json("You are not allowed to delete this user!");
  }
});

// logout route
app.post("/api/logout", verify, (req, res) => {
  const refereshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refereshToken);
  res.status(200).json("You logged out successfully.");
});

app.listen(5000, () => console.log("Backend server listening on port 5000"));
