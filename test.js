const axios = require('axios');

const jwt = require('jsonwebtoken');
const { SECRET } = require('./secret');

const token = jwt.sign(
  {
    sub: 'foo.bar',
    // token valid for 30 days
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30,
  },
  SECRET
);

console.log(token);

// const run = async () => {
//   console.log('No Token');
//   try {
//     const res = await axios.get('http://localhost:3000/hello');
//     console.log('Result', JSON.stringify(res.data, null, 2));
//   } catch (error) {
//     console.error('Something went wrong', error);
//   }
// };

// run();
