###
https://github.com/dropbox/zxcvbn/
NOTES:
Our options so far to use this in Aman Raqami
  - Use the NPM package
  - Import the minified JS file in the project and use it
###


matching = require './matching'
scoring = require './scoring'
time_estimates = require './time_estimates'
feedback = require './feedback'

time = -> (new Date()).getTime()

###
https://github.com/dropbox/zxcvbn/tree/master#usage

 NOTES:
 @param password (required) 
 @param user_inputs (optional) is an array of strings that zxcvbn will treat as an extra dictionary.
        This can be whatever list of strings you like, but is meant for user inputs from other
        fields of the form, like name and email. That way a password that includes a user's
        personal information can be heavily penalized.
 @return a result object of the following properties:
  - guesses: estimated guesses needed to crack password
  - guesses_log10: order of magnitude of result.guesses
  - crack_times_seconds: dictionary of back-of-the-envelope crack time
                          estimations, in seconds, based on a few scenarios:
        - online_throttling_100_per_hour:       online attack on a service that ratelimits password auth attempts.
        - online_no_throttling_10_per_second:   online attack on a service that doesn't ratelimit, or where an attacker has outsmarted ratelimiting.
        - offline_slow_hashing_1e4_per_second:  offline attack. assumes multiple attackers, proper user-unique salting, and a slow hash function
        - offline_fast_hashing_1e10_per_second: offline attack with user-unique salting but a fast hash.
  - crack_times_display: same keys as result.crack_times_seconds, with friendlier display string values:
                          "less than a second", "3 hours", "centuries", etc.
  - score: Integer from 0-4 (useful for implementing a strength bar):
        - 0 -> too guessable: risky password. (guesses < 10^3)
        - 1 -> very guessable: protection from throttled online attacks. (guesses < 10^6)
        - 2 -> somewhat guessable: protection from unthrottled online attacks. (guesses < 10^8)
        - 3 -> safely unguessable: moderate protection from offline slow-hash scenario. (guesses < 10^10)
        - 4 -> very unguessable: strong protection from offline slow-hash scenario. (guesses >= 10^10)
  - feedback: verbal feedback to help choose better passwords. set when score <= 2.
        - feedback.warning: explains what's wrong, eg. 'this is a top-10 common password'.
                            *not always set -- sometimes an empty string.
        - feedback.suggestions: a possibly-empty list of suggestions to help choose a less guessable password.
                                eg. 'Add another word or two'.
  - sequence: the list of patterns that zxcvbn based the guess calculation on.
  - calc_time: how long it took zxcvbn to calculate an answer in milliseconds.
###
zxcvbn = (password, user_inputs = []) ->
  start = time()
  # reset the user inputs matcher on a per-request basis to keep things stateless
  sanitized_inputs = []
  for arg in user_inputs
    if typeof arg in ["string", "number", "boolean"]
      sanitized_inputs.push arg.toString().toLowerCase()
  matching.set_user_input_dictionary sanitized_inputs
  matches = matching.omnimatch password
  result = scoring.most_guessable_match_sequence password, matches
  result.calc_time = time() - start
  attack_times = time_estimates.estimate_attack_times result.guesses
  for prop, val of attack_times
    result[prop] = val
  result.feedback = feedback.get_feedback result.score, result.sequence
  result

module.exports = zxcvbn
