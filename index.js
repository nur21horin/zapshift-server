const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET);

const port = process.env.PORT || 3000;
const crypto = require("crypto");
const { create } = require("domain");

//middlewar
const admin = require("firebase-admin");

const serviceAccount = require("./fir-zap-shift-firebase-adminsdk-fbsvc-7ca8e86903.json");
const { count } = require("console");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

function generateTrackingId() {
  const prefix = "PRCL";
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();

  return `${prefix}-${date}-${random}`;
}

app.use(express.json());
app.use(cors());

const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }

  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decoded.email;

    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.a1cksfq.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();

    const db = client.db("zap_shift_db");
    const parcelsCollection = db.collection("parcels");
    const userCollection = db.collection("users");
    const paymentCollection = db.collection("payments");
    const ridersCollection = db.collection("riders");
    const trackingsCollection = db.collection("trackings");
    const logsCollection = db.collection("logs");

    //middleware with database access

    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);
      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    const logTracking = async (trackingId, status) => {
      const log = {
        trackingId,
        status,
        details: status.split("_").join(" "),
        createdAt: new Date(),
      };
      const result = await trackingsCollection.insertOne(log);
      return result;
    };

    //logs related api
    app.post("/logs", verifyFBToken, async (req, res) => {
      const { message, userEmail } = req.body;
      await logsCollection.insertOne({
        message,
        userEmail,
        time: new Date(),
      });
      res.send({ success: true });
    });
    app.get("/logs", verifyFBToken, async (req, res) => {
      const logs = await logsCollection
        .find({ userEmail: req.user.email })
        .sort({ time: -1 })
        .limit(50)
        .toArray();
      res.send(logs);
    });
    //  users related api

    app.get("/users", verifyFBToken, async (req, res) => {
      try {
        const searchText = req.query.search || "";
        const role = req.query.role || "all";
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 6;
        const skip = (page - 1) * limit;

        // Build query
        let query = {};
        if (searchText) {
          query.$or = [
            { displayName: { $regex: searchText, $options: "i" } },
            { email: { $regex: searchText, $options: "i" } },
          ];
        }
        if (role !== "all") {
          query.role = role;
        }

        const users = await userCollection
          .find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        const total = await userCollection.countDocuments(query);

        res.send({ users, total });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Server error" });
      }
    });

    app.patch(
      "/users/:id/role",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const roleInfo = req.body;
        const query = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            role: roleInfo.role,
          },
        };
        const result = await userCollection.updateOne(query, updateDoc);
        res.send(result);
      },
    );
    app.patch("/users/:id/notifications", async (req, res) => {
      const id = req.params.id;
      const { emailNotifications, smsNotifications } = req.body;
      const result = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { notifications: { emailNotifications, smsNotifications } } },
      );
      res.send(result);
    });

    app.patch("/users/:id", verifyFBToken, async (req, res) => {
      const id = req.params.id;
      const { name, phone, address, photoURL } = req.body;

      const result = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            name,
            phone,
            address,
            photoURL,
          },
        },
      );

      res.send(result);
    });

    app.get("/users/:email/role", async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = await userCollection.findOne(query);
      res.send({ role: user?.role || "user" });
    });
    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;
      const user = await userCollection.findOne({ email });
      res.send(user);
    });

    app.patch("/users/email/:email", verifyFBToken, async (req, res) => {
      if (req.params.email !== req.decoded_email) {
        return res.status(403).send({ message: "forbidden" });
      }

      const result = await userCollection.updateOne(
        { email: req.params.email },
        { $set: req.body },
      );

      res.send(result);
    });

    app.post("/users", async (req, res) => {
      const user = req.body;
      user.role = "user";
      user.createdAt = new Date();

      const email = user.email;
      const userExist = await userCollection.findOne({ email });
      if (userExist) {
        return res.send({ message: "user exist" });
      }
      const result = await userCollection.insertOne(user);
      res.send(result);
    });
    // app.get("/parcels", (req, res) => {});

    //parcels api
    app.get("/parcels", async (req, res) => {
      const query = {};
      const { email, deliveryStatus } = req.query;
      if (email) {
        query.senderEmail = email;
      }
      if (deliveryStatus) {
        query.deliveryStatus = deliveryStatus;
      }
      const options = { sort: { createdAt: -1 } };
      const cursor = parcelsCollection.find(query, options);
      const result = await cursor.toArray();
      res.send(result);
    });

    app.get(`/parcels/delivery-status/stats`, async (req, res) => {
      const stats = await parcelsCollection
        .aggregate([
          {
            $group: {
              _id: "$deliveryStatus",
              count: { $sum: 1 },
            },
          },
        ])
        .toArray();
      res.send(stats);
    });
    app.post("/parcels", async (req, res) => {
      const parcel = req.body;

      //parcel created time
      parcel.createdAt = new Date();

      const result = await parcelsCollection.insertOne(parcel);
      res.send(result);
    });

    app.get("/parcels/riders", async (req, res) => {
      const { riderEmail, deliveryStatus } = req.query;
      const query = {};
      if (riderEmail) {
        query.riderEmail = riderEmail;
      }
      if (deliveryStatus) {
        query.deliveryStatus = deliveryStatus;
      }

      const cursor = parcelsCollection.find(query);
      const result = await cursor.toArray();
      res.send(result);
    });
    app.get("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await parcelsCollection.findOne(query);
      res.send(result);
    });

    app.patch("/parcels/:id/status", async (req, res) => {
      const { deliveryStatus, riderId, trackingId } = req.body;

      const query = { _id: new ObjectId(req.params.id) };
      const updatedDoc = {
        $set: {
          deliveryStatus: deliveryStatus,
        },
      };

      if (deliveryStatus === "parcel_delivered") {
        // update rider information
        const riderQuery = { _id: new ObjectId(riderId) };
        const riderUpdatedDoc = {
          $set: {
            workStatus: "available",
          },
        };
        const riderResult = await ridersCollection.updateOne(
          riderQuery,
          riderUpdatedDoc,
        );
      }

      const result = await parcelsCollection.updateOne(query, updatedDoc);
      // log tracking
      logTracking(trackingId, deliveryStatus);

      res.send(result);
    });

    app.delete("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };

      const result = await parcelsCollection.deleteOne(query);
      res.send(result);
    });
    app.patch("/parcels/:id", async (req, res) => {
      const { parcelId, riderId, riderName, riderEmail } = req.body;
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          deliveryStatus: "driver_assigned",
          riderId: riderId,
          riderName: riderName,
          riderEmail: riderEmail,
        },
      };
      const result = await parcelsCollection.updateOne(query, updatedDoc);
      const riderQuery = { _id: new ObjectId(riderId) };
      const riderUpdateDoc = {
        $set: {
          workStatus: "in_delivery",
        },
      };
      const riderResult = await ridersCollection.updateOne(
        riderQuery,
        riderUpdateDoc,
      );
      res.send(riderResult);
    });
    app.patch(
      "/parcels/:id/assign-rider",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const parcelId = req.params.id;
        const { riderId, riderEmail, riderName } = req.body;

        const query = { _id: new ObjectId(parcelId) };

        const updateDoc = {
          $set: {
            riderId,
            riderEmail,
            riderName,
            deliveryStatus: "assigned",
            assignedAt: new Date(),
          },
        };

        const result = await parcelsCollection.updateOne(query, updateDoc);
        res.send(result);
      },
    );

    //payment related api

    app.post("/create-checkout-session", async (req, res) => {
      try {
        const paymentInfo = req.body;
        const amount = Number(paymentInfo.cost) * 100;
        if (!amount || amount <= 0) {
          return res.status(400).send({ message: "Invalid payment amount" });
        }
        const session = await stripe.checkout.sessions.create({
          line_items: [
            {
              price_data: {
                currency: "usd",
                unit_amount: amount,
                product_data: {
                  name: paymentInfo.parcelName || "Parcel Delivery Payment",
                },
              },

              quantity: 1,
            },
          ],
          customer_email: paymentInfo.senderEmail,
          mode: "payment",
          metadata: {
            parcelId: paymentInfo.parcelId,
            parcelName: paymentInfo.parcelName,
            //parcelName: session.metadata.parcelName,
          },

          success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,

          cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
        });
        res.send({ url: session.url });
      } catch (error) {
        console.error("Stripe Error:", error.message);
        res.status(500).send({ message: error.message });
      }
    });

    app.patch("/payment-success", async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        if (!sessionId) {
          return res.status(400).send({ message: "Session ID required" });
        }

        const session = await stripe.checkout.sessions.retrieve(sessionId);

        if (session.payment_status !== "paid") {
          return res.send({ success: false });
        }

        const parcelId = session.metadata.parcelId;
        const transactionId = session.payment_intent;

        // ✅ Check duplicate payment in payments collection
        const paymentExist = await paymentCollection.findOne({ transactionId });
        if (paymentExist) {
          return res.send({
            message: "already exist",
            transactionId,
            trackingId: paymentExist.trackingId,
          });
        }

        const trackingId = generateTrackingId();

        // ✅ Update parcel using parcelId (CORRECT)
        const parcelQuery = { _id: new ObjectId(parcelId) };

        const update = {
          $set: {
            paymentStatus: "paid",
            paidAt: new Date(),
            deliveryStatus: "pending-pickup",
            transactionId,
            trackingId,
          },
        };

        const result = await parcelsCollection.updateOne(parcelQuery, update);

        if (result.modifiedCount === 0) {
          return res.status(404).send({ message: "Parcel not found" });
        }

        // ✅ Save payment record
        const payment = {
          amount: session.amount_total / 100,
          currency: session.currency,
          customerEmail: session.customer_email,
          parcelId,
          parcelName: session.metadata.parcelName,
          transactionId,
          paymentStatus: session.payment_status,
          trackingId,
          paidAt: new Date(),
        };

        await paymentCollection.insertOne(payment);

        res.send({
          success: true,
          transactionId,
          trackingId,
        });
      } catch (error) {
        console.error("Payment Success Error:", error.message);
        res.status(500).send({ success: false, message: error.message });
      }
    });

    //payment related api
    app.get("/payments", verifyFBToken, async (req, res) => {
      const email = req.query.email;
      const query = {};

      if (email) {
        query.customerEmail = email;
        if (email !== req.decoded_email) {
          return res.status(403).send({ message: "forbidden access" });
        }
      }

      const cursor = paymentCollection.find(query).sort({ paidAt: -1 });
      const result = await cursor.toArray();
      res.send(result);
    });

    //riders api
    app.post("/riders", async (req, res) => {
      const rider = req.body;
      rider.status = "pending";
      rider.createdAt = new Date();

      const result = await ridersCollection.insertOne(rider);
      res.send(result);
    });

    app.patch("/riders/:id", verifyFBToken, async (req, res) => {
      try {
        const { status } = req.body; // ✅ extract STRING
        const id = req.params.id;

        const query = { _id: new ObjectId(id) };

        const updatedDoc = {
          $set: { status: status, workStatus: "available" },
        };

        const result = await ridersCollection.updateOne(query, updatedDoc);
        if (status === "approved") {
          const email = req.body.email;
          const useQuery = { email };
          const updateUser = {
            $set: {
              role: "rider",
            },
          };
          const userResult = await userCollection.updateOne(
            useQuery,
            updateUser,
          );
        }
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to update rider" });
      }
    });

    app.get("/riders", async (req, res) => {
      const { status, district, workStatus } = req.query;

      const query = {};
      if (status) {
        query.status = status;
      }

      if (district) {
        query.district = district;
      }
      if (workStatus) {
        query.workStatus = workStatus;
      }
      const cursor = ridersCollection.find(query);
      const result = await cursor.toArray();
      res.send(result);
    });

    app.delete("/riders/:id", verifyFBToken, async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await ridersCollection.deleteOne(query);
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: "Failed to delete rider" });
      }
    });
    //tracking related apis
    app.get("/trackings/:trackingId/logs", async (req, res) => {
      const trackingId = req.params.trackingId;
      const query = { trackingId };
      const result = await trackingsCollection.find(query).toArray();
      res.send(result);
    });
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!",
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);
app.get("/", (req, res) => {
  res.send("zap is shifting shift");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
