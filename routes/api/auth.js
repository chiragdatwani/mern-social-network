const express = require("express");
const auth = require("../../middleware/auth");
const router = express.Router();
const User = require("../../models/Users");
// route    GET api/auth
// desc     Test route
// access   Public
router.get("/", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (error) {
    res.status(500).send("Server Error");
  }
});

module.exports = router;
