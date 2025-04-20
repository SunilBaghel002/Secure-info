const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
const axios = require("axios");

const app = express();
const server = http.createServer(app);

app.use(express.static("public"));
// Configure CORS for Socket.IO
const io = socketIo(server, {
  cors: {
    origin: ["http://localhost:3000", "http://127.0.0.1:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  },
  maxHttpBufferSize: 5 * 1024 * 1024, // Allow up to 5MB for file uploads
});

// Configure CORS for Express
app.use(
  cors({
    origin: ["http://localhost:3000", "http://127.0.0.1:3000"],
    methods: ["GET", "POST", "DELETE"],
    credentials: true,
  })
);
app.use(express.json({ limit: "5mb" }));

// Connect to MongoDB
mongoose
  .connect("mongodb://127.0.0.1:27017/chat-app", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"));

// User Schema
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", UserSchema);

// Room Schema
const RoomSchema = new mongoose.Schema({
  roomId: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastActive: { type: Date, default: Date.now },
  messages: [
    {
      type: { type: String, enum: ["text", "image", "audio"], default: "text" },
      text: String,
      sender: String,
      data: String, // For base64 image/audio
      timestamp: { type: Date, default: Date.now },
    },
  ],
});
const Room = mongoose.model("Room", RoomSchema);

// User Activity Schema
const UserActivitySchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  ipAddress: String,
  location: {
    city: String,
    country: String,
    latitude: Number,
    longitude: Number,
  },
  roomId: String,
  joinTime: { type: Date, default: Date.now },
  exitTime: Date,
  action: { type: String, enum: ["join", "exit"], required: true },
});
const UserActivity = mongoose.model("UserActivity", UserActivitySchema);

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    const decoded = jwt.verify(token, "secret");
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// Admin Middleware (simple password check)
const adminMiddleware = async (req, res, next) => {
  const { adminPassword } = req.body;
  if (adminPassword !== "supersecret123") {
    // Replace with secure auth in production
    return res.status(403).json({ error: "Invalid admin password" });
  }
  next();
};

// Routes
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    const token = jwt.sign({ id: user._id, email }, "secret", {
      expiresIn: "1h",
    });
    res.json({ user: { email }, token });
  } catch (err) {
    res.status(400).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user._id, email }, "secret", {
      expiresIn: "1h",
    });
    res.json({ user: { email }, token });
  } catch (err) {
    res.status(400).json({ error: "Login failed" });
  }
});

app.get("/api/auth/verify", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user: { email: user.email } });
  } catch (err) {
    res.status(400).json({ error: "Verification failed" });
  }
});

app.post("/api/rooms/create", authMiddleware, async (req, res) => {
  const { roomId, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const room = new Room({ roomId, password: hashedPassword });
    await room.save();
    res.json({ message: "Room created" });
  } catch (err) {
    res.status(400).json({ error: "Room creation failed" });
  }
});

app.post("/api/rooms/join", authMiddleware, async (req, res) => {
  const { roomId, password } = req.body;
  try {
    const room = await Room.findOne({ roomId });
    if (!room || !(await bcrypt.compare(password, room.password))) {
      return res.status(401).json({ error: "Invalid room ID or password" });
    }
    res.json({ message: "Joined room" });
  } catch (err) {
    res.status(400).json({ error: "Failed to join room" });
  }
});

app.delete("/api/rooms/:roomId/messages", authMiddleware, async (req, res) => {
  const { roomId } = req.params;
  try {
    await Room.updateOne({ roomId }, { $set: { messages: [] } });
    io.to(roomId).emit("messagesCleared");
    res.json({ message: "Messages cleared" });
  } catch (err) {
    res.status(400).json({ error: "Failed to clear messages" });
  }
});

// Admin Routes
app.post("/api/admin/rooms", adminMiddleware, async (req, res) => {
  try {
    const rooms = await Room.find().select(
      "roomId createdAt lastActive messages"
    );
    res.json(rooms);
  } catch (err) {
    res.status(400).json({ error: "Failed to fetch rooms" });
  }
});

app.post("/api/admin/activity", adminMiddleware, async (req, res) => {
  try {
    const activities = await UserActivity.find().sort({ joinTime: -1 });
    res.json(activities);
  } catch (err) {
    res.status(400).json({ error: "Failed to fetch activity" });
  }
});

// Get IP-based location
const getLocation = async (ip) => {
  try {
    const response = await axios.get(`https://ipapi.co/${ip}/json/`);
    const { city, country_name, latitude, longitude } = response.data;
    return { city, country: country_name, latitude, longitude };
  } catch (err) {
    return { city: "Unknown", country: "Unknown", latitude: 0, longitude: 0 };
  }
};

// Socket.IO
const roomUsers = {};

io.on("connection", (socket) => {
  const token = socket.handshake.auth.token;
  const ip = socket.handshake.address;
  let userEmail = "Unknown";

  // Verify token
  try {
    const decoded = jwt.verify(token, "secret");
    userEmail = decoded.email;
  } catch (err) {
    socket.disconnect();
    return;
  }

  socket.on("joinRoom", async (roomId) => {
    socket.join(roomId);

    // Initialize room users
    if (!roomUsers[roomId]) {
      roomUsers[roomId] = new Set();
    }

    // Add user to room
    roomUsers[roomId].add(userEmail);

    // Log join activity
    const location = await getLocation(ip);
    await UserActivity.create({
      userEmail,
      ipAddress: ip,
      location,
      roomId,
      action: "join",
    });

    // Update room lastActive
    await Room.updateOne({ roomId }, { $set: { lastActive: new Date() } });

    // Emit events
    io.to(roomId).emit("userJoined", userEmail);
    io.to(roomId).emit("roomUsersUpdate", { count: roomUsers[roomId].size });

    // Send room messages
    const room = await Room.findOne({ roomId });
    if (room) {
      socket.emit("messages", room.messages);
    }
  });

  socket.on(
    "message",
    async ({ roomId, type, text, data, sender, timestamp }) => {
      const message = {
        type,
        text,
        data,
        sender,
        timestamp: new Date(timestamp),
      };
      await Room.updateOne({ roomId }, { $push: { messages: message } });
      await Room.updateOne({ roomId }, { $set: { lastActive: new Date() } });
      io.to(roomId).emit("message", message);
    }
  );

  socket.on("disconnect", async () => {
    for (const roomId in roomUsers) {
      if (roomUsers[roomId].has(userEmail)) {
        roomUsers[roomId].delete(userEmail);

        // Log exit activity
        const location = await getLocation(ip);
        await UserActivity.create({
          userEmail,
          ipAddress: ip,
          location,
          roomId,
          action: "exit",
          exitTime: new Date(),
        });

        // Update room lastActive
        await Room.updateOne({ roomId }, { $set: { lastActive: new Date() } });

        // Emit events
        io.to(roomId).emit("userLeft", userEmail);
        io.to(roomId).emit("roomUsersUpdate", {
          count: roomUsers[roomId].size,
        });

        if (roomUsers[roomId].size === 0) {
          delete roomUsers[roomId];
        }
        break;
      }
    }
  });
});

server.listen(5000, () =>
  console.log("Server running on http://localhost:5000")
);
