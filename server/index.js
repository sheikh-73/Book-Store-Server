const port = 4000;

const express = require("express");
const cors = require("cors");
const mysql = require("mysql");
const path = require("path");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const multer = require("multer");
const { error } = require("console");
const { json } = require("body-parser");

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static("/Uploads"));

const database = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "bookstore"
});

database.connect((error) => {
    if(error)
    {
        console.log("Error: "+error);
        throw error;
    }
    else
    {
        console.log("Database connect...");
    }
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "Uploads");
    },
    filename: (req, file, cb) => {
        cb(null, file.fieldname+"_"+Date.now()+path.extname(file.originalname));
    }
});

const upload = multer({storage: storage});

// for new customer sign up:
app.post("/customer/signup", upload.single("image"), async(req, res) => {
    const hashPass = await bcrypt.hash(req.body.password, 10);
    const sql = "select * from customers where email=?";
    database.query(sql, [req.body.email], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        else if(r.length >0)
        {
            return res.status(400).json({message: "email already existed"});
        }
        const sql2 = "insert into customers (first_name, last_name, email, phone, password, role, image) values (?)";
        const values = [
            req.body.first_name,
            req.body.last_name,
            req.body.email,
            req.body.phone,
            hashPass,
            req.body.role,
            req.file.filename
        ];
        database.query(sql2, [values], (error, result) => {
            if(error)
            {
                console.log("Error: "+error);
                return res.status(404).json(error);
            }
            res.status(200).json({message: `welcome ${req.body.first_name} ${req.body.last_name}.`});
        });
    });
});

// for customer sign in:
app.post("/customer/signin", (req, res) => {
    const sql = "select * from customers where email=?";
    database.query(sql, [req.body.email], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        else if(r.length === 0)
        {
            return res.status(400).json({message: "email not found."});
        }
        const customer = r[0];
        bcrypt.compare(req.body.password, customer.password, (error, isMatch) => {
            if(error)
            {
                console.log("Error: "+error);
                return res.status(404).json(error);
            }
            else if(!isMatch)
            {
                return res.status(400).json({message: "invalid password."});
            }
            const token = jwt.sign({id: customer.customer_id}, "key", {expiresIn: "1d"});
            res.cookie("token", token);
            res.status(201).json({message: "sign in successful."});
        });
    });
});

// for customer forget password:
app.put("/customer/forget-password/:token", async(req, res) => {
    const decode = await jwt.verify(req.params.token, "key");
    const hashPass = await bcrypt.hash(req.body.password, 10);
    const sql = "update customers set password=? where customer_id=?";
    database.query(sql, [hashPass, decode.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "update successful."});
    });
});

// for customer profile view:
app.get("/customer/profile/:token", async(req, res) => {
    const decode = await jwt.verify(req.params.token, "key");
    const sql = "select * from customers where customer_id=?";
    database.query(sql, [decode.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for delete customer account:
app.delete("/delete/customer/:token", async(req, res) => {
    const decode = await jwt.verify(req.params.token, "key");
    const sql = "delete from customers where customer_id=?";
    database.query(sql, [decode.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "account delete successful."});
    });
});

// for view all customers:
app.get("/all-customers", (req, res) => {
    const sql = "select * from customers";
    database.query(sql, (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for new author sign up:
app.post("/author/signup", upload.single("image"), async(req, res) => {
    const hashPass = await bcrypt.hash(req.body.password, 10);
    const sql = "select * from authors where email=?";
    database.query(sql, [req.body.email], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        else if(r.length >0)
        {
            return res.status(400).json({message: "email already existed"});
        }
        const sql2 = "insert into authors (first_name, last_name, nationality, email, password, role, image) values (?)";
        const values = [
            req.body.first_name,
            req.body.last_name,
            req.body.nationality,
            req.body.email,
            hashPass,
            req.body.role,
            req.file.filename
        ];
        database.query(sql2, [values], (error, result) => {
            if(error)
            {
                console.log("Error: "+error);
                return res.status(404).json(error);
            }
            res.status(200).json({message: `welcome ${req.body.first_name} ${req.body.last_name}.`});
        });
    });
});

// for author sign in:
app.post("/author/signin", (req, res) => {
    const sql = "select * from authors where email=?";
    database.query(sql, [req.body.email], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        else if(r.length === 0)
        {
            return res.status(400).json({message: "email not found."});
        }
        const author = r[0];
        bcrypt.compare(req.body.password, author.password, (error, isMatch) => {
            if(error)
            {
                console.log("Error: "+error);
                return res.status(404).json(error);
            }
            else if(!isMatch)
            {
                return res.status(400).json({message: "invalid password."});
            }
            const token = jwt.sign({id: author.author_id}, "key", {expiresIn: "1d"});
            res.cookie("token", token);
            res.status(201).json({message: "sign in successful."});
        });
    });
});

// for author forget password:
app.put("/author/forget-password/:token", async(req, res) => {
    const decode = await jwt.verify(req.params.token, "key");
    const hashPass = await bcrypt.hash(req.body.password, 10);
    const sql = "update authors set password=? where author_id=?";
    database.query(sql, [hashPass, decode.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "update successful."});
    });
});

// for author profile view:
app.get("/author/profile/:token", async(req, res) => {
    const decode = await jwt.verify(req.params.token, "key");
    const sql = "select * from authors where author_id=?";
    database.query(sql, [decode.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for delete author account:
app.delete("/delete/author/:token", async(req, res) => {
    const decode = await jwt.verify(req.params.token, "key");
    const sql = "delete from authors where author_id=?";
    database.query(sql, [decode.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "account delete successful."});
    });
});

// for view all authors:
app.get("/all-authors", (req, res) => {
    const sql = "select * from authors";
    database.query(sql, (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for creating new book:
app.post("/book/create", upload.single("image"), (req, res) => {
    const sql = "insert into books (tittle, genre, price, author_id, image) values(?)";
    const values = [
        req.body.tittle,
        req.body.genre,
        req.body.price,
        req.body.author_id,
        req.file.filename
    ];
    database.query(sql, [values], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "new book create successful."});
    });
});

// for view all books:
app.get("/all-books", (req, res) => {
    const sql = "select * from books";
    database.query(sql, (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for get a single book:
app.get("/book/:id", (req, res) => {
    const sql = "select * from books where book_id=?";
    database.query(sql, [req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for get author by id:
app.get("/author/:id", (req, res) => {
    const sql = "select * from authors where author_id=?";
    database.query(sql, [req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for delete a book:
app.delete("/book/delete/:id", (req, res) => {
    const sql = "delete from books where book_id=?";
    database.query(sql, [req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "book delete successful."});
    });
});

// for update book:
app.put("/book/update/:id", (req, res) => {
    const sql = "update books set tittle=?, genre=?, price=?, author_id=? where book_id=?";
    const values = [
        req.body.tittle,
        req.body.genre,
        req.body.genre,
        req.body.author_id
    ];
    database.query(sql, [...values, req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "update book successful."});
    });
});

// for get a customer by her/his id:
app.get("/customer/:id", (req, res) => {
    const sql = "select * from customers where customer_id=?";
    database.query(sql, [req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for new order:
app.post("/order/new", (req, res) => {
    const sql = "insert into orders (date, total_amount, customer_id) values(?)";
    const values = [
        req.body.date,
        req.body.total_amount,
        req.body.customer_id
    ];
    database.query(sql, [values], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        console.log(r.insertId);

        req.body.items.map(item => {
            const sql2 = "insert into order_details (quantity, subtotal, order_id, book_id) values(?)";
            const values2 = [
                item.quantity,
                item.subtotal,
                r.insertId,
                item.book_id
            ];
            database.query(sql2, [values2], (error2, r2) => {
                if(error2)
                {
                    console.log("Error: "+error);
                    return res.status(404).json(error);
                }
            });
        });
        res.status(201).json({data: r, message: "order create successful."});
    });
});

// for view all orders:
app.get("/all-orders", (req, res) => {
    const sql = "select * from orders";
    database.query(sql, (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for view a single order:
app.get("/order/:id", (req, res) => {
    const sql = "select * from orders where order_id=?";
    database.query(sql, [req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

app.delete("/order/delete/:id", (req, res) => {
    const sql = "delete from orders where order_id=?";
    database.query(sql, [req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "delete order successful."});
    });
});

// for add to cart:
app.post("/add-to-cart", (req, res) => {
    const sql = "insert into cart (quantity, total_price, book_id, customer_id) values(?)";
    const values = [
        req.body.quantity,
        req.body.total_price,
        req.body.book_id,
        req.body.customer_id
    ];
    database.query(sql, [values], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "cart add successful."});
    });
});

// get all carts by a customer:
app.get("/all-carts/:token", async(req, res) => {
    const decode = await jwt.verify(req.params.token, "key");
    const sql = "select * from cart where customer_id=?";
    database.query(sql, [decode.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// get a single cart:
app.get("/cart/:id", (req, res) => {
    const sql = "select * from cart where cart_id=?";
    database.query(sql, [req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// delete a cart:
app.delete("/cart/delete/:id", (req, res) => {
    const sql = "delete from cart where cart_id=?";
    database.query(sql, [req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "cart delete successful."});
    });
});

// update a cart:
app.put("/cart/update/:id", (req, res) => {
    const sql = "update cart set quantity=?, total_price=? where cart_id=?";
    const values = [
        req.body.quantity,
        req.body.total_price
    ];
    database.query(sql, [...values, req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({message: "cart update successful."});
    });
});

// for view all order details:
app.get("/all-orderdetails", (req, res) => {
    const sql = "select * from order_details";
    database.query(sql, (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});

// for a single order details:
app.get("/orderdetails/:id", (req, res) => {
    const sql = "select * from order_details where id=?";
    database.query(sql, [req.params.id], (error, r) => {
        if(error)
        {
            console.log("Error: "+error);
            return res.status(404).json(error);
        }
        res.status(201).json({data: r});
    });
});


app.listen(port, "0.0.0.0", () => {
    console.log("server running...");
});