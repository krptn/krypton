const core = require('@actions/core');
const github = require('@actions/github');

try {
  // `who-to-greet` input defined in action metadata file
  const con = core.getInput('content');
  const repa = core.getInput('repo');
  const patha = core.getInput('path');
  var result = await octokit.request('PUT /repos/{repo}/contents/{path}', {
    repo: repa,
    path: patha,
    message: 'update sec file',
    content: con
  })
  console.log(result)
} catch (error) {
  core.setFailed(error.message);
}
