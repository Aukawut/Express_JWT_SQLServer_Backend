const express = require("express")
const app = express()
const cors = require("cors")
const sql = require("mssql")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const { check, validationResult } = require("express-validator")
const saltRounds = 10
require("dotenv").config()
const secret = process.env.SECRET_KEY
const bodyParser = require("body-parser")
app.use(cors())
app.use(bodyParser.json())
const PORT = process.env.PORT
const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PWD,
  server: "localhost",
  database: process.env.DB_NAME,
  options: {
    encrypt: true, // for azure
    trustServerCertificate: true, // change to true for local dev / self-signed certs
  },
}
const pool = new sql.ConnectionPool(config)
app.get("/users", (req, res) => {
  pool.connect((err) => {
    if (err) {
      console.log(`Error connecting to database: ${err}`)
      return
    }
    const request = pool.request()
    const query = "SELECT name,email,level FROM tb_users"
    request.query(query, (err, results) => {
      if (err) {
        res.json({
          err: true,
          msg: err,
        })
      } else {
        res.json(results.recordset)
      }
    })
  })
})
app.get("/users/:id", (req, res) => {
  const id = req.params.id
  pool.connect((err) => {
    if (err) {
      console.log(`Error connecting to database: ${err}`)
      return
    }
    const request = pool.request()
    const query = "SELECT name,email,level FROM tb_users WHERE id = @id"
    request.input("id", sql.Int, id)
    request.query(query, (err, results) => {
      if (err) {
        res.json({
          err: true,
          msg: err,
        })
      } else {
        res.json(results.recordset)
      }
    })
  })
})

//Register
app.post(
  "/register",
  [
    check("email", "Error email format !").isEmail(),
    check("password", "Password must be 6 or more characters long.").isLength({
      min: 6,
    }),
  ],
  (req, res) => {
    const errors = validationResult(req)
    const { name, username, password, email } = req.body
    const level = "user"
    if (!name || !username || !email || !password) {
      res.json({
        err: true,
        msg: "Error input!",
      })
    } else {
      if (!errors.isEmpty()) {
        res.json({ err: true, msg: errors.array()[0].msg })
      } else {
        pool.connect((err) => {
          if (err) {
            console.log(`Error connecting to database: ${err}`)
            return
          }
          bcrypt.genSalt(saltRounds, function (err, salt) {
            bcrypt.hash(password.trim(), salt, function (err, hash) {
              const request = pool.request()
              const requestUser = pool.request()
              requestUser.input("username", sql.NVarChar, username.trim())
              requestUser.query(
                "SELECT * FROM tb_users WHERE username = @username",
                (err, results) => {
                  if (err) {
                    res.json({
                      err: true,
                      msg: err,
                    })
                  } else {
                    if (results.recordset.length > 0) {
                      res.json({
                        err: true,
                        msg: "Username duplicate!",
                      })
                    } else {
                      const query =
                        "INSERT INTO tb_users (username,name,email,password,level) VALUES (@username,@name,@email,@password,@level)"
                      request.input("name", sql.NVarChar, name.trim())
                      request.input("email", sql.NVarChar, email.trim())
                      request.input("password", sql.NVarChar, hash)
                      request.input("level", sql.NVarChar, level)
                      request.input("username", sql.NVarChar, username.trim())
                      request.query(query, (err, results) => {
                        if (err) {
                          res.json({
                            err: true,
                            msg: err,
                          })
                        } else {
                          res.json({
                            err: false,
                            msg: "Register successfully!",
                            result: results,
                          })
                        }
                      })
                    }
                  }
                }
              )
            })
          })
        })
      }
    }
  }
)
//Login
app.post(
  "/login",
  [
    check("username", "Please input your username").not().isEmpty(),
    check("password", "Please input your password").not().isEmpty(),
  ],
  (req, res) => {
    const { username, password } = req.body
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      res.json({ err: true, msg: errors.array()[0].msg })
    } else {
      pool.connect((err) => {
        if (err) {
          console.log(`Error connecting to database: ${err}`)
          return
        } else {
          const request = pool.request()
          const requestUser = pool.request()
          requestUser.input("username", sql.NVarChar, username.trim())
          requestUser.query(
            "SELECT * FROM tb_users WHERE username = @username",
            (err, results) => {
              if (err) {
                res.json({
                  err: true,
                  msg: err,
                })
              } else {
                if (results.recordset.length > 0) {
                  const password_hash = results.recordset[0].password

                  bcrypt.compare(
                    password,
                    password_hash,
                    function (err, result) {
                      if (err) {
                        res.json({
                          err: true,
                          msg: err,
                        })
                      } else {
                        if (result) {
                          const name_user = results.recordset[0].name
                          const token = jwt.sign({ name: name_user }, secret, {
                            expiresIn: "3h",
                          })

                          res.json({
                            err: false,
                            msg: "Login successfully!",
                            token: token,
                          })
                        } else {
                          res.json({
                            err: true,
                            msg: "Username or Password Invalid!",
                          })
                        }
                      }
                    }
                  )
                } else {
                  res.json({
                    err: true,
                    msg: "Username or Password Invalid!",
                  })
                }
              }
            }
          )
        }
      })
    }
  }
)

//Auth
app.post("/auth", (req, res) => {
  const tokenUser = req.headers.authorization

  if (!tokenUser) {
    res.json({
      err: true,
      msg: "Token invalid!",
    })
  } else {
    const token = tokenUser.split(" ")[1]
    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        res.json({
          err: true,
          msg: "Token invalid!",
        })
      } else {
        if (decoded) {
          res.json({
            err: false,
            msg: "Verify successfully!",
            decoded: decoded,
          })
        } else {
          res.json({
            err: true,
            msg: "Token invalid!",
          })
        }
      }
    })
  }
})

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})
