"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserSchema = exports.user = void 0;
const mongoose_1 = __importDefault(require("mongoose"));
exports.user = new mongoose_1.default.Schema({
    username: {
        type: String,
        required: [true, 'Please provide unique Username'],
        unique: true,
    },
    password: {
        type: String,
        required: [true, 'Please provide a password'],
        unique: false,
    },
    email: {
        type: String,
        required: [true, 'Please provide a unique email'],
        unique: true,
    },
    firstName: { type: String },
    lastName: { type: String },
    mobile: { type: Number },
    address: { type: String },
    profile: { type: String },
    role: {
        type: String,
        enum: ['admin', 'user'],
        default: 'user',
    },
    verifiedUser: {
        type: Boolean,
        default: false,
    },
    verificationToken: { type: String },
    verifiedDate: { type: String },
    tokenExpirationDate: {
        type: Date,
    },
}, {
    collection: 'usercollection',
    timestamps: true,
});
const UserSchema = mongoose_1.default.model('user', exports.user);
exports.UserSchema = UserSchema;
