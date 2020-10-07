const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // @doc https://jwt.io/
const config = require('config');
const { check, validationResult } = require('express-validator'); // @doc https://express-validator.github.io/docs/

const User = require('../../models/User');

// @route   GET api/auth
// @desc    Return current User based on decoded jwt token
// @access  Public
// @params route'',middleware*,callback function(), *middleware will be called when this route recieves the GET request.
router.get('/', auth, async (req, res) => {
  try {
    // Find and return user based on id and omit the password field.
    const user = await User.findById(req.user.id).select('-password'); // NOTE: req.user is assigned in auth middleware 
    res.json(user);
  } catch(err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

// @route   POST api/auth
// @desc    Authenticate user and get token / login request
// @access  Public
// @params route'',validations[],callback function()
router.post(
  // ROUTE
  '/',
  // USER VALIDATIONS
  [
    check('email', 'Please include a valid email')
      .isEmail(),
    check('password', 'Password is required')
      .exists()
  ],
  // CALLBACK FUNCTION
  async (req, res) => {
    // Handle Initial Validation Errors
    const errors = validationResult(req); // Extracts the validation errors from a request and makes them available in a Result object. @functions: .isEmpty(), .array()
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() }); // Status 400: bad request
    }

    const { email, password } = req.body;

    try {
      let user = await User.findOne({ email }); // Query Users table by email

      // Error no user exists
      if (!user) {
        return res
          .status(400) 
          .json({ errors: [{ msg: 'Invalid Credentials' }] }); // Security tip, use same response for both missing user and password.
      }

      // Compares password given with encrypted password in DB
      const isMatch = await bcrypt.compare(password, user.password);

      // Error if incorrect password
      if (!isMatch) {
        return res
          .status(400) 
          .json({ errors: [{ msg: 'Invalid Credentials' }] });
      }

      // JWT
      const payload = {
        user: {
          id: user.id
        }
      };

      jwt.sign(
        payload, 
        config.get('jwtSecret'),
        { expiresIn: 360000 }, // Set to 3600 in deployment
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch(err) {
      console.error(err.message);
      res.status(500).send('Server error'); // Status 500: Internal Server Error
    }
  }
);

module.exports = router;
