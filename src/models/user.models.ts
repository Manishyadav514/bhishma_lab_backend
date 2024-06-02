import mongoose from 'mongoose'

export const user = new mongoose.Schema({
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
},
    {
        collection: 'usercollection',
        timestamps: true,
    }
)

const UserSchema = mongoose.model('user', user)

export { UserSchema }
