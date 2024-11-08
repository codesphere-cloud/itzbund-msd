export const eachWeek = (start: Date, end: Date) => {
  // go to the start of the day
  start = new Date(start);
  end = new Date(end);
  start.setUTCHours(0, 0, 0, 0);
  end.setUTCHours(0, 0, 0, 0);
  const dates = [start.getTime()];

  let currentDate = start;
  while (currentDate < end) {
    currentDate = new Date(currentDate.getTime() + 7 * 24 * 60 * 60 * 1000);
    // go to the start of the day
    currentDate.setUTCHours(0, 0, 0, 0);
    dates.push(Math.min(currentDate.getTime(), end.getTime()));
  }

  return dates;
};

export const eachDay = (start: Date, end: Date) => {
  // go to the start of the day
  start = new Date(start);
  end = new Date(end);
  start.setUTCHours(0, 0, 0, 0);
  end.setUTCHours(0, 0, 0, 0);
  const dates = [start.getTime()];

  let currentDate = start;
  while (currentDate < end) {
    currentDate = new Date(currentDate.getTime() + 24 * 60 * 60 * 1000);
    // go to the start of the day
    currentDate.setUTCHours(0, 0, 0, 0);
    dates.push(Math.min(currentDate.getTime(), end.getTime()));
  }

  return dates;
};
