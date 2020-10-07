const express = require('express');
const router = express.Router();
const normalize = require('normalize-url');
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // @doc https://jwt.io/
const config = require('config');
const { check, validationResult } = require('express-validator'); // @doc https://express-validator.github.io/docs/

const User = require('../../models/User');

// @route   POST api/users
// @desc    Register user
// @access  Public
// @params route'',validations[],callback function()
router.post(
  // ROUTE
  '/',
  // USER VALIDATIONS
  [
    check('name', 'Name is required')
      .not()
      .isEmpty(),
    check('email', 'Please include a valid email')
      .isEmail(),
    check('password', 'Please enter a password with 6 or more characters')
      .isLength({ min: 6 })
  ],
  // CALLBACK FUNCTION
  async (req, res) => {
    // Handle Initial Validation Errors
    const errors = validationResult(req); // Extracts the validation errors from a request and makes them available in a Result object. @functions: .isEmpty(), .array()
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() }); // Status 400: bad request
    }

    const { name, email, password } = req.body;

    try {
      let user = await User.findOne({ email }); // Query Users table by email

      // Error if user exists
      if (user) {
        return res.status(400).json({ errors: [{ msg: 'User already exists' }] })
      }

      // Gravatar setup
      const avatar = normalize(
        gravatar.url(email, {
          s: '200', //size
          r: 'pg', //rating
          d: 'mm' //default
        }),
        { forceHttps: true }
      );

      // Create new User object
      user = new User({
        name,
        email,
        avatar,
        password
      });

      // Encrypt password with bcryptjs
      const salt = await bcrypt.genSalt(10); // Documentation recommends 10 rounds.

      user.password = await bcrypt.hash(password, salt);

      // Save user to DB
      await user.save();

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
