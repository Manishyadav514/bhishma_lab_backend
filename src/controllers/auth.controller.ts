import { Request, Response } from 'express'
import { createAccessToken, createRefreshToken, } from '../middleware/auth.middleware'
import { HttpStatusCodes } from '../enum/StatusCode'
// import { attachCookiesToResponse } from '../middleware/auth.middleware'
// import UserSchema from '../models/UserSchema'
import tokenModels from '../models/token.models'
// import { HttpStatusCodes } from '../enum/StatusCode'
// import * as CustomAPIError from '../errors'
// import { sendResetPasswordEmail, hashString } from '../utils'
import { sendResetPasswordEmail } from '../utils/sendResetPasswordEmail'
import { hashString } from '../utils/createHash'
import { BadRequestError } from '../errors'
// import crypto from 'crypto'
import bcrypt from 'bcrypt'
import validator from 'validator'
import { UserSchema } from '../models/user.models'
import { CustomAPIError } from '../errors'
import { comparePassword } from '../utils/auth.utils'

const registerUser = async (req: Request, res: Response): Promise<Response> => {
  const { email, password, username, firstName, lastName, mobile, address, profile, } = req.body
  // Validate input fields
  if (!email || !password || !username) {
    return res.status(400).json({
      status: '400',
      message: 'Please fill all the fields',
    })
  }

  // Validate email format
  if (!validator.isEmail(email)) {
    return res.status(400).json({
      status: '400',
      message: 'Email is not valid',
    })
  }

  // Validate password strength
  if (!validator.isStrongPassword(password,
    {
      minLength: 8,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    })) {
    return res.status(400).json({
      status: '400',
      message: 'Password is not strong enough',
    })
  }
  const userAgent = req.get('UserSchema-Agent')
  try {
    // Check if email already exists
    const exists = await UserSchema.findOne({ username })
    if (exists) {
      return res.status(400).json({
        status: '400',
        message: 'username already exists',
      })
    }

    // Generate salt and hash password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    // Create new user
    const newUser = new UserSchema({
      email,
      password: hashedPassword,
      username,
      firstName,
      lastName,
      mobile,
      address,
      profile,
      role: 'admin',
      verifiedUser: false,
      verifiedDate: '',
    })

    // Save new user
    const newentry = await newUser.save()

    // reuire for email verification
    // const tempOrigin = req.get('origin')
    // const protocol = req.protocol
    // const host = req.get('host')
    // const forwardedHost = req.get('x-forwarded-host')
    // const forwardedProtocol = req.get('x-forwarded-proto')

    //   await sendVerificationEmail({
    //     name: user.name,
    //     email: user.email,
    //     verificationToken: user.verificationToken,
    //     origin,
    //   })

    // Respond with success
    // return res.status(201).json({
    //   status: '201',
    //   email: newentry.email,
    //   token,
    //   username: username || '',
    //   firstName: firstName || '',
    //   lastName: lastName || '',
    //   mobile: mobile || '',
    //   address: address || '',
    //   profile: profile || '',
    //   verifiedUser: false,
    //   verifiedDate: '',
    // })

    const userData = {
      _id: newentry._id,
      username: newentry.username,
      email: newentry.email,
      firstName: newentry.firstName,
      lastName: newentry.lastName,
      mobile: newentry.mobile,
      address: newentry.address,
      profile: newentry.profile,
    }


    const accessToken = createAccessToken(`${newentry._id}`)
    const refreshToken = await createRefreshToken(newentry._id, userAgent)

    return res.status(200).json({
      message: 'Login successful',
      accessToken,
      refreshToken,
      user: userData,
    })

  } catch (error) {
    // Log the error for internal debugging
    console.error('Internal Server Error:', error)

    // Respond with appropriate error message
    return res.status(500).json({
      status: '500',
      message: 'UserSchema not created due to an internal error. Please try again later.',
    })
  }
}


const loginUser = async (req: Request, res: Response): Promise<Response> => {
  const { password, username } = req.body
  // Validate input fields
  if (!password || !username) {
    return res.status(400).json({
      status: '400',
      message: 'Please fill all the fields',
    })
  }

  try {
    const userAgent = req.get('UserSchema-Agent')
    const userObj = await UserSchema.findOne({ username })

    if (!userObj) {
      return res.status(404).json({
        message: 'User not found',
        status: '404 Not Found',
      })
    }

    const userPassword: string = userObj.password || ''

    const validPassword = await bcrypt.compare(
      req.body.password,
      userPassword
    )

    if (!validPassword) {
      return res.status(400).json({
        message: 'Invalid password',
        status: '400',
      })

    }

    const userData = {
      _id: userObj._id,
      username: userObj.username,
      email: userObj.email,
      firstName: userObj.firstName,
      lastName: userObj.lastName,
      mobile: userObj.mobile,
      address: userObj.address,
      profile: userObj.profile,
    }

    const accessToken = createAccessToken(`${userObj._id}`)
    let refreshToken = ''

    // check for existing token
    const existingToken = await tokenModels.findOne({ user: userObj._id })

    if (existingToken) {
      const { isValid } = existingToken
      if (!isValid) {
        throw new CustomAPIError.UnauthorizedError('Invalid Credentials')
      }
      refreshToken = existingToken.refreshToken
      // attachCookiesToResponse({ res, accessToken, refreshToken })
    }
    else {
      refreshToken = await createRefreshToken(userObj._id, userAgent)
      // attachCookiesToResponse({ res, accessToken, refreshToken })
    }

    return res.status(200).json({
      message: 'Login successful',
      accessToken,
      refreshToken,
      user: userData,
    })

  } catch (error) {
    console.log(error)
    return res.status(500).json({
      status: '500 Internal Server Error',
      message: '500 Internal Server Error, User not logged in',
    })
  }
}

const logoutUser = async (req: Request, res: Response) => {
  const { userID } = req.body

  if (!userID) {
    res.status(400).json({
      status: '400',
      message: 'user id is missing',
    })
  }

  await tokenModels.findOneAndDelete({ user: userID })

  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  })

  res.status(HttpStatusCodes.OK).json({ msg: 'user logged out!' })
}



const verifyEmail = async (req: Request, res: Response) => {
  const { verificationToken, username } = req.body
  const user = await UserSchema.findOne({ username })

  if (!user) {
    throw new CustomAPIError.UnauthorizedError('Verification Failed')
  }

  if (user.verificationToken !== verificationToken) {
    throw new CustomAPIError.UnauthorizedError('Verification Failed')
  }

  user.verifiedUser = true,
    user.verificationToken = ''
  user.verifiedDate = new Date().toISOString() // Use a date string for consistency

  await user.save()

  res.status(200).json({ msg: 'Email Verified' })
}



const userObj = async (req: Request, res: Response) => {
  const { username, password } = req.body

  if (!username || !password) {
    throw new BadRequestError('Please provide email and password')
  }
  const userObj = await UserSchema.findOne({ username })

  if (!userObj) {
    throw new CustomAPIError.UnauthorizedError('Invalid Credentials')
  }
  const isPasswordCorrect = await comparePassword(password, userObj.password)

  if (!isPasswordCorrect) {
    throw new CustomAPIError.UnauthorizedError('Invalid Credentials')
  }
  if (!userObj.verifiedUser) {
    throw new CustomAPIError.UnauthorizedError('Please verify your email')
  }

  const userData = {
    _id: userObj._id,
    username: userObj.username,
    email: userObj.email,
    firstName: userObj.firstName,
    lastName: userObj.lastName,
    mobile: userObj.mobile,
    address: userObj.address,
    profile: userObj.profile,
  }

  return res.status(200).json({

    user: userData,
  })
}


const forgotPassword = async (req: Request, res: Response) => {
  const { username } = req.body
  if (!username) {
    throw new BadRequestError('Please provide valid email')
  }

  const user = await UserSchema.findOne({ username })

  if (user) {
    const passwordToken = createAccessToken(`${user._id}`)
    // send email
    const origin = 'http://localhost:3000'
    await sendResetPasswordEmail({
      name: `${user.firstName} ${user.lastName}`,
      email: user.email,
      token: passwordToken,
      origin,
    })

    const tenMinutes = 1000 * 60 * 10
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes)

    user.verificationToken = hashString(passwordToken)
    user.tokenExpirationDate = passwordTokenExpirationDate
    await user.save()
  }

  res
    .status(HttpStatusCodes.OK)
    .json({ msg: 'Please check your email for reset password link' })
}

const resetPassword = async (req: Request, res: Response) => {
  const { token, username, password } = req.body
  if (!token || !username || !password) {
    throw new BadRequestError('Please provide all values')
  }
  const user = await UserSchema.findOne({ username })

  if (user) {

    if (
      user.verificationToken === hashString(token)
    ) {
      user.password = password
      user.verificationToken = null
      user.tokenExpirationDate = null
      await user.save()
    }
  }

  res.send('reset password')
}

export {
  userObj,
  logoutUser,
  registerUser,
  loginUser,
  verifyEmail,
  forgotPassword,
  resetPassword,
}
