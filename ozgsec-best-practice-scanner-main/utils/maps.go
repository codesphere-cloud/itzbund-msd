package utils

// mutates the first provided map
// does a deep merge of the maps
func Merge[Key comparable, Value any](maps ...map[Key]Value) map[Key]Value {
	// make sure to remove all nil maps
	nonNilMaps := Filter(maps, func(m map[Key]Value) bool {
		return m != nil
	})

	if len(nonNilMaps) == 0 {
		return nil
	}
	if len(nonNilMaps) == 1 {
		return nonNilMaps[0]
	}

	res := make(map[Key]Value)

	for _, m := range nonNilMaps {
		for k, v := range m {
			// check if k does already exists in res
			if _, ok := res[k]; ok {
				// if it does, check if the value is a map
				// if it is, merge the maps
				// if it is not, overwrite the value
				if _, ok := any(v).(map[Key]Value); ok {
					// merge the maps
					res[k] = any(Merge(any(res[k]).(map[Key]Value), any(v).(map[Key]Value))).(Value)
				}
			}
			// just overwrite the value
			res[k] = v
		}
	}
	return res
}
