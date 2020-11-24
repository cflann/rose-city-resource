const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

async function initialize(passport, pool) {

  const authenticateUser = async (email, password, done) => {
    await pool.query(
      `SELECT * FROM production_user WHERE email = $1`, [email],
      async (err, results) => {
        if (err) { throw err; }
        if (results.rows.length > 0) {
          const user = results.rows[0];
          await bcrypt.compare(password, user.password, async (err, isMatch) => {
            if (err) {
              console.log(err);
            }
            if (isMatch) {
              return await done(null, user);
            } else {
              //password is incorrect
              return await done(null, false, { message: "Password is incorrect" });
            }
          });
        } else {
          /* CHECK THIS. doesn't seem to be reaching this far. */
          return await done(null, false, {
            message: "No user with that email address"
          });
        }
      }
    );
  };

  passport.use(
    new LocalStrategy(
      { usernameField: "email", passwordField: "password", roleField: 'role' },
      authenticateUser 
    )
  );

  passport.serializeUser((user, done) => done(null, user.id));

  passport.deserializeUser(async (id, done) => {
    await pool.query(`SELECT * FROM production_user WHERE id = $1`, [id], async (err, results) => {
      if (err) {
        return await done(err);
      }
      return await done(null, results.rows[0]);
    });
  });
}

module.exports = initialize;