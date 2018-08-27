const bcrypt = require('bcrypt');

'use strict';
module.exports = (sequelize, DataTypes) => {
  var user = sequelize.define('user', {
    firstname: DataTypes.STRING,
    lastname: DataTypes.STRING,
    email: {
      type: DataTypes.STRING,
      validate: {
        isEmail: {
          msg: 'That is not a valid email address.  Please try again.'
        }
      }
    },
    password: {
      type: DataTypes.STRING,
      validate: {
        len: {
          args: [8, 16],
          msg: 'Password must be between 8 and 16 characters.'
        }
      }
    },
    dob: DataTypes.DATE,
    admin: DataTypes.BOOLEAN,
    facebookId: DataTypes.STRING,
    facebookToken: DataTypes.STRING,
    image: {
      type: DataTypes.STRING,
      validate: {
        isUrl: {
          msg: 'That is not a valid url for your photo.'
        }
      }
    }
  }, {
    hooks: {
      beforeCreate: function(pendingUser) {
        if(pendingUser && pendingUser.password) {
          const hash = bcrypt.hashSync(pendingUser.password, 10);
          pendingUser.password = hash;
        }
      }
    }
  });
  user.associate = function(models) {
    // associations can be defined here
  };

  user.prototype.isValidPassword = function(typedPassword) {
    return bcrypt.compareSync(typedPassword, this.password);
  }

  return user;
};
