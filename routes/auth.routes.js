const router = require("express").Router();
const UserModel = require('../models/User.model')
const bcrypt = require("bcryptjs")

router.get("/signup", (req, res, next) => {
    res.render('auth/signup.hbs')
})

router.post("/signup", (req, res, next) => {
    let {username, password} = req.body
    let salt = bcrypt.genSaltSync(10);
    let hash = bcrypt.hashSync(password, salt);
    
    if (username == "") {
        res.render("auth/signup", {error:"Please enter a username"})
        return;
    }

    let passwordRegEx = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[0-9a-zA-Z]{8,}$/
    if (!passwordRegEx.test(password)) {
        res.render("auth/signup", {error:"Please enter a valid password: Minimum eight characters, at least one lower case, one upper case one number"})
        return;
    }


    UserModel.create({username, password: hash})
        .then(()=> {
            res.redirect('/');
        })
        .catch((err)=> {
            next(err)
        })
})

router.get("/signin", (req, res, next) => {
    res.render("auth/signin.hbs")
})

router.post("/signin", (req, res, next) => {
    let {username, password} = req.body
    UserModel.find({username})
    .then((usernameResponse) => {
        if(usernameResponse.length) {        
            
            let userObj = usernameResponse[0]
            let isMatching = bcrypt.compareSync(password, userObj.password);
       
            if (isMatching){
                req.session.myProperty = userObj;
                res.redirect("/")
            }
            else {
                res.render("auth/signin.hbs", {error:"Failed to signin"})
                return
            }
        }
        else {
            res.render("auth/signin.hbs", {error:"Username does not exist"})
            return
        }

        //console.log(usernameResponse)
    })
    .catch((err)=> {
        next(err)
    })
})

const checkLogIn = (req, res, next) => {
    if (req.session.myProperty ) {
      //invokes the next available function
      next()
    }
    else {
      res.redirect('/signin')
    }
}


router.get("/main", checkLogIn, (req, res, next) => {
    res.render("auth/main.hbs")
})



router.get("/private", checkLogIn, (req, res, next) => {
    res.render("auth/private.hbs")
})



module.exports = router