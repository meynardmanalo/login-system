const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
require("dotenv").config();


const ADMIN_NAME = "TheFlowerMaster";
const ADMIN_EMAIL = "theflowermaster@admin.com";
const ADMIN_PASSWORD = "Flower123";

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["admin", "client"], default: "client" },
  status: { type: String, enum: ["active", "suspended"], default: "active" }
}, { timestamps: { createdAt: "createdAt", updatedAt: false } });

const roleSchema = new mongoose.Schema({
  role_name: { type: String, required: true, unique: true },
  description: { type: String }
});

const userRoleSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  role: { type: mongoose.Schema.Types.ObjectId, ref: "Role", required: true },
  assignedAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Role = mongoose.model("Role", roleSchema);
const UserRole = mongoose.model("UserRole", userRoleSchema);

async function run() {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log("Connected to MongoDB.");

  
  let adminRole = await Role.findOne({ role_name: "Admin" });
  if (!adminRole) {
    adminRole = await Role.create({ role_name: "Admin", description: "Full system access" });
    console.log("Created Admin role.");
  }

  
  const existing = await User.findOne({ email: ADMIN_EMAIL.toLowerCase() });
  if (existing) {
    if (existing.role !== "admin") {
      existing.role = "admin";
      await existing.save();
      console.log("Updated the existing account role to Admin.");
    }
    console.log(`A user with email ${ADMIN_EMAIL} already exists (id: ${existing._id}). No changes made.`);
    await mongoose.disconnect();
    return;
  }

  const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
  const adminUser = await User.create({
    name: ADMIN_NAME,
    email: ADMIN_EMAIL.toLowerCase(),
    password: hashedPassword,
    role: "admin",
    status: "active"
  });

  await UserRole.create({ user: adminUser._id, role: adminRole._id });

  console.log(`Admin account created: ${adminUser.name} <${adminUser.email}>`);
  console.log("Role assigned: Admin");

  await mongoose.disconnect();
}

run().catch((err) => {
  console.error("Error seeding admin:", err);
  process.exit(1);
});