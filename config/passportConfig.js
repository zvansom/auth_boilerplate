// Use env variables
require('dotenv').config();

// Requires
const passport = require('passport');
const passportFacebookStrategy = require('passport-facebook').Strategy;
const passportLocalStrategy = require('passport-local').Strategy;

// Declare variables
const db = require('../models');

// Provide serialize/deserialize functions so we can use session
passport.serializeUser(function(user, callback) { callback(null, user.id); });
passport.deserializeUser( (id, callback) => {
  db.user.findById(id)
  .then( user => { callback(null, user); })
  .catch( err => { callback(err, null); }) });

// Do the actual login
passport.use( new passportLocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, (email, password, callback) => {
  db.user.findOne({ where: { email } })
  .then( foundUser => {
    if(!foundUser || !foundUser.isValidPassword(password)) {
      callback(null, null);
    } else {
      callback(null, foundUser);
    }
  }).catch( err => callback(err, null))
}));

passport.use( new passportFacebookStrategy({
  clientID: process.env.FB_APP_ID,
  clientSecret: process.env.FB_APP_SECRET,
  callbackURL: process.env.BASE_URL + '/auth/callback/facebook',
  profileFields: ['id', 'email', 'displayName'],
  enableProof: true
}, function(accessToken, refreshToken, profile, done){
  // See if we have an email address we can use for idnetifying the user.
  const facebookEmail = profile.emails ? profile.emails[0].value : null;

  // See if the email exists in the users table
  db.user.findOne({
    where: { email: facebookEmail } })
    .then( existingUser => {
      if(existingUser && facebookEmail){
        // This user is a returning user - update facebookId and token
        existingUser.updateAttributes({
          facebookId: profile.id,
          facebookToken: accessToken
        })
        .then( updatedUser => done(null, updatedUser) )
        .catch(done);
      } else {
        // The person is a new user, create a new entry for them
        // Parse the user's name
        const usernameArr = profile.displayName.split(' ');
        db.user.findOrCreate({
          where: { facebookId: profile.id },
          defaults: {
            facebookToken: accessToken,
            email: facebookEmail,
            firstname: usernameArr[0],
            lastname: usernameArr[usernameArr.length - 1],
            admin: false,
            image: 'https://png.icons8.com/ios/1600/person-gemaile-filled.png',
            dob: profile.birthday
          }
        }).spread( (user, wasCreated) => {
          if(wasCreated) {
            // This was expected
            done(null, user);
          } else {
            // This user was not new after all.  This could happen if the user changed their email on Fb since last log in
            user.facebookToken = accessToken;
            user.email = facebookEmail;
            user.save().then( updatedUser => done(null, updatedUser) )
            .catch(done);
          }
        });
      }
    });
}));

module.exports = passport;
